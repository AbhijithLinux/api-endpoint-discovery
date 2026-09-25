"""endpoint_discovery.py — Abhijith's multi-source API endpoint discovery.

Sources:
  1. crawler      — passive filter over crawl() records (original MVP logic).
  2. javascript   — static inspection of <script> resources for API string refs.
  3. openapi/swagger — passive probe of common spec locations, extract `paths` keys.
  4. common_path  — small controlled wordlist of common API paths (GET only).

Backward compatible:
    discover_endpoints(crawl_records)  # original behaviour, crawler source only
    discover_endpoints(crawl_records, target_url)  # all sources

Output: [{"url", "source", "sources"}]; "sources" lists every mechanism
that found the URL (single-element list when only one source matched).
The extra keys are ignored by endpoint_analysis (which reads "url" plus
provenance "source"/"sources"/"found_in"), so Abhishek's interface is kept.
"""

from __future__ import annotations

import json
import re
from urllib.parse import urljoin, urlparse

import requests

PATH_HINTS = ("/api/", "/v1/", "/v2/", "/graphql", "/chat", "/openai/", "/logs")

# Extra hint used ONLY for JS-extracted strings (Juice Shop uses /rest/*).
JS_PATH_HINTS = ("/api/", "/api", "/v1/", "/v2/", "/rest/", "/graphql")

OPENAPI_LOCATIONS = (
    "/swagger.json",
    "/openapi.json",
    "/api/swagger.json",
    "/api/openapi.json",
    "/swagger/v1/swagger.json",
    "/api-docs",
    "/v3/api-docs",
    "/api-docs/swagger.json",
    "/api-docs/openapi.json",
)

# Small controlled MVP wordlist — no brute forcing.
COMMON_API_PATHS = (
    "/api",
    "/api/users",
    "/api/products",
    "/api/login",
    "/api/auth",
    "/api/orders",
    "/api/users/",
    "/api/products/",
    "/api/v1/users",
    "/api/v1/products",
    "/v1/users",
    "/v1/products",
    "/graphql",
    "/rest/user/login",
    "/chat",
    "/openai/logs",
)

_TIMEOUT = 5
_MAX_JS_FILES = 10
_MAX_JS_BYTES = 500_000

# Accept as "exists": success/redirect or auth/method-gated responses.
# 404/5xx (and network errors) mean "not an endpoint".
_LIVE_STATUSES = set(list(range(200, 400)) + [401, 403, 405])

# Matches quoted strings that look like API paths: "/api/users", '/v1/x', ...
_JS_API_RE = re.compile(
    r"""["'`](/(?:api|v1|v2|rest|graphql)(?:[A-Za-z0-9_\-./{}:$]*))["'`]"""
)
_SRC_RE = re.compile(r"""<script[^>]+src=["'`]([^"'`#]+)["'`]""", re.I)


def is_api_candidate(record):
    url = record.get("url", "")
    content_type = (record.get("content_type") or "").split(";")[0].strip().lower()
    path = urlparse(url).path.lower()

    if any(hint in path for hint in PATH_HINTS):
        return True
    if content_type == "application/json" or (
        content_type.startswith("application/") and content_type.endswith("+json")
    ):
        return True
    if path.endswith(".json"):
        return True
    return False


def _origin(url):
    p = urlparse(url)
    return f"{p.scheme}://{p.netloc}"


def _add(store, url, source):
    """store: dict url -> {"url","source","sources"}. Merge sources on dupes."""
    if not url:
        return
    url = url.split("#")[0].strip()
    if not url or not urlparse(url).netloc:
        return
    if url in store:
        entry = store[url]
        if source not in entry["sources"]:
            entry["sources"].append(source)
            entry["source"] = entry["sources"][0]
    else:
        store[url] = {"url": url, "source": source, "sources": [source]}


def _finalize(store):
    out = []
    for entry in store.values():
        out.append(
            {
                "url": entry["url"],
                "source": entry["sources"][0],
                "sources": list(entry["sources"]),
            }
        )
    return out


def _crawler_source(store, crawl_records):
    for record in crawl_records or []:
        url = record.get("url") if isinstance(record, dict) else None
        if not url or not isinstance(record, dict):
            continue
        if is_api_candidate(record):
            _add(store, url, "crawler")


def _javascript_source(store, target_url, session):
    """Fetch root HTML, resolve <script src>, regex API-ish strings. GET only."""
    try:
        resp = session.get(target_url, timeout=_TIMEOUT)
        html = resp.text[:1_000_000]
    except requests.RequestException:
        return
    srcs = _SRC_RE.findall(html)[:_MAX_JS_FILES]
    # Inline scripts in the HTML itself are also worth scanning.
    texts = [html]
    for src in srcs:
        js_url = urljoin(target_url, src)
        if urlparse(js_url).netloc != urlparse(target_url).netloc:
            continue  # same-origin only for MVP
        try:
            r = session.get(js_url, timeout=_TIMEOUT)
            ctype = (r.headers.get("Content-Type") or "").lower()
            if "javascript" not in ctype and not js_url.endswith(".js"):
                continue
            texts.append(r.text[:_MAX_JS_BYTES])
        except requests.RequestException:
            continue
    origin = _origin(target_url)
    for text in texts:
        for m in _JS_API_RE.findall(text):
            path = m.strip()
            low = path.lower()
            if not any(h in low for h in JS_PATH_HINTS):
                continue
            if " " in path or "\\n" in path:
                continue
            _add(store, urljoin(origin, path), "javascript")


def _openapi_source(store, target_url, session):
    origin = _origin(target_url)
    for loc in OPENAPI_LOCATIONS:
        doc_url = origin + loc
        try:
            r = session.get(
                doc_url, timeout=_TIMEOUT, headers={"Accept": "application/json"}
            )
        except requests.RequestException:
            continue
        if r.status_code != 200:
            continue
        try:
            doc = json.loads(r.text[:1_000_000])
        except (ValueError, json.JSONDecodeError):
            continue
        paths = doc.get("paths") if isinstance(doc, dict) else None
        if not isinstance(paths, dict):
            continue
        label = "swagger" if "swagger" in loc else "openapi"
        for p in paths:
            if not isinstance(p, str) or not p.startswith("/"):
                continue
            _add(store, origin + p, label)


def _common_path_source(store, target_url, session, extra_paths=None, verbose=False):
    GREEN, RESET = "\033[92m", "\033[0m"
    origin = _origin(target_url)
    paths = list(COMMON_API_PATHS) + list(extra_paths or [])
    total = len(paths)
    hits = 0
    print(f"  [wordlist] brute-forcing {total} paths...", flush=True)
    for i, path in enumerate(paths, 1):
        url = origin + path
        if url in store:
            # Still record the source if another source found it first.
            _add(store, url, "common_path")
            hits += 1
            print(f"  [{i}/{total}] {path} -> {GREEN}HIT (merged, {hits} found){RESET}", flush=True)
            continue
        try:
            r = session.get(url, timeout=_TIMEOUT, allow_redirects=False)
        except requests.RequestException as e:
            if verbose:
                print(f"  [{i}/{total}] {path} -> error", flush=True)
            else:
                print(f"  [{i}/{total}] checked, {hits} found", end="\r", flush=True)
            continue
        if r.status_code in _LIVE_STATUSES:
            _add(store, url, "common_path")
            hits += 1
            print(f"  [{i}/{total}] {path} -> {GREEN}HIT [{r.status_code}] ({hits} found){RESET}", flush=True)
        elif verbose:
            print(f"  [{i}/{total}] {path} -> {r.status_code}", flush=True)
        else:
            print(f"  [{i}/{total}] checked, {hits} found", end="\r", flush=True)
    print(f"  [wordlist] done: {hits}/{total} live{RESET if hits else ''}", flush=True)


def load_wordlist(path):
    """Load extra paths from file. Ignores blanks/#comments, ensures leading /."""
    out = []
    with open(path, encoding="utf-8", errors="ignore") as f:
        for line in f:
            s = line.strip().split()[0] if line.strip() else ""
            if not s or s.startswith("#"):
                continue
            if not s.startswith("/"):
                s = "/" + s
            if s not in out:
                out.append(s)
    return out


def discover_endpoints(
    crawl_records,
    target_url=None,
    enable_javascript=True,
    enable_openapi=True,
    enable_common_paths=True,
    wordlist=None,
    extra_paths=None,
    verbose=False,
):
    """Multi-source discovery. Always includes the passive crawler source.

    `target_url` enables network sources (javascript/openapi/common_path).
    With no target_url the behaviour is identical to the original MVP.
    Only GET requests are sent; 404/5xx/network errors are skipped silently.
    """
    store: dict[str, dict] = {}
    _crawler_source(store, crawl_records)

    if target_url:
        target_url = str(target_url).strip()
        if urlparse(target_url).netloc:
            session = requests.Session()
            session.trust_env = False
            session.headers.update({"User-Agent": "API-Discovery/1.0"})
            try:
                if enable_javascript:
                    _javascript_source(store, target_url, session)
                if enable_openapi:
                    _openapi_source(store, target_url, session)
                if enable_common_paths:
                    wl = []
                    if wordlist:
                        wl += load_wordlist(wordlist)
                    if extra_paths:
                        wl += list(extra_paths)
                    _common_path_source(store, target_url, session, extra_paths=wl, verbose=verbose)
            finally:
                session.close()
    return _finalize(store)
