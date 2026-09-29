"""endpoint_discovery.py — Abhijith's multi-source API endpoint discovery.

Sources (docs-first order — brute-force wordlist runs LAST as fallback):
  1. crawler      — passive filter over crawl() records (original MVP logic).
  2. javascript   — static inspection of <script> resources for API string refs.
  3. docs         — fetch API documentation pages found during the crawl
                    (REST/OpenAPI, GraphQL, gRPC, WebSocket, webhooks, SOAP)
                    and extract real endpoints from them. Includes the
                    classic spec-location probe (openapi/swagger) as fallback.
  4. common_path  — small controlled wordlist of common API paths (GET only),
                    used only after docs (fallback).

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

PATH_HINTS = ("/api/", "/v1/", "/v2/", "/graphql", "/chat", "/openai/", "/logs", "/resources/")

# Extra hint used ONLY for JS-extracted strings (Juice Shop uses /rest/*).
JS_PATH_HINTS = ("/api/", "/api", "/v1/", "/v2/", "/rest/", "/graphql", "/resources/")

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
    "/api/v2/resources",
    "/api/v2/resources/books",
    "/api/v2/resources/books/all",
)

_TIMEOUT = 5
_MAX_JS_FILES = 10
_MAX_JS_BYTES = 500_000

# Accept as "exists": success/redirect or auth/method-gated responses.
# 404/5xx (and network errors) mean "not an endpoint".
_LIVE_STATUSES = set(list(range(200, 400)) + [401, 403, 405])

# Matches quoted strings that look like API paths: "/api/users", '/v1/x', ...
_JS_API_RE = re.compile(
    r"""["'`](/(?:api|v1|v2|rest|graphql|resources)(?:[A-Za-z0-9_\-./{}:$]*))["'`]"""
)
_SRC_RE = re.compile(r"""<script[^>]+src=["'`]([^"'`#]+)["'`]""", re.I)

# Substrings identifying API documentation pages (any protocol). Used to
# pick doc pages out of crawl records AND to prioritize them in the crawler.
DOC_PAGE_HINTS = (
    "swagger", "openapi", "redoc", "api-docs", "api/docs", "api-doc",
    "developer", "api-reference", "api_reference", "reference/api",
    "graphql", "graphiql", "playground", "altair",
    "grpc", "proto", "bufbuild",
    "websocket", "web-socket", "/ws", "wsdl", "soap",
    "webhook", "web-hook", "asyncapi", "postman", "insomnia",
    "schema", ".proto", ".wsdl",
)

# <a href="..."> links inside doc pages pointing at machine-readable specs.
_DOC_SPEC_HREF_RE = re.compile(
    r"""<a[^>]+href=["'`]([^"'`#]+\.(?:json|ya?ml|wsdl|proto|graphqls?)(?:\?[^"'`#]*)?)["'`]""",
    re.I,
)
# ws(s):// URLs (WebSocket endpoints) mentioned in docs.
_WS_URL_RE = re.compile(r"""["'`](wss?://[^"'`\s<>]+)["'`]""", re.I)
# SOAP: <soap:address location="..."/> and operation names.
_SOAP_ADDR_RE = re.compile(
    r"""<soap(?::\w+)?:address[^>]+location=["'`]([^"'`]+)["'`]""", re.I
)
_SOAP_OP_RE = re.compile(
    r"""<wsdl:operation[^>]+name=["'`]([^"'`]+)["'`]""", re.I
)
# Webhook paths: "/webhooks/...", "/hook/...", quoted.
_WEBHOOK_PATH_RE = re.compile(
    r"""["'`](/(?:webhooks?|hooks?|callbacks?)(?:[A-Za-z0-9_\-./{}:$]*))["'`]"""
)
# Generic REST-ish quoted paths inside docs (broader than the JS regex).
_DOC_API_PATH_RE = re.compile(
    r"""["'`](/(?:api|v1|v2|v3|rest|graphql|grpc|ws|soap|resources)(?:[A-Za-z0-9_\-./{}:$]*))["'`]"""
)
# Bare (unquoted) API paths as they appear in human-readable docs, e.g.
# <code>/api/v2/resources/books/all</code> or "GET /api/v2/resources/books?id=1".
# Query strings are kept so parameterized routes survive.
_DOC_BARE_PATH_RE = re.compile(
    r"""(?<![A-Za-z0-9_:/])(/(?:api(?:/v\d+)?/resources/[A-Za-z0-9_\-./{}:$]*)(?:\?[^\s\"'<>()]*)?)""",
)

_MAX_DOC_PAGES = 15
_MAX_DOC_BYTES = 1_000_000


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


def is_doc_page(url):
    """True if a crawled URL looks like API documentation (any protocol)."""
    try:
        low = (urlparse(url).path or "").lower() + url.lower()
    except (ValueError, UnicodeError):
        return False
    return any(h in low for h in DOC_PAGE_HINTS)


def _doc_pages_from_crawl(crawl_records):
    """Pick doc-page URLs out of crawl records, deduped, order-preserved."""
    out, seen = [], set()
    for record in crawl_records or []:
        if not isinstance(record, dict):
            continue
        url = record.get("url")
        if not isinstance(url, str) or not url:
            continue
        clean = url.split("#")[0].strip()
        if not clean or clean in seen:
            continue
        if is_doc_page(clean):
            seen.add(clean)
            out.append(clean)
        if len(out) >= _MAX_DOC_PAGES:
            break
    return out


def _extract_openapi_paths(text, origin):
    """Parse an OpenAPI/Swagger JSON doc body -> list of absolute endpoint URLs."""
    try:
        doc = json.loads(text[:_MAX_DOC_BYTES])
    except (ValueError, json.JSONDecodeError):
        return []
    paths = doc.get("paths") if isinstance(doc, dict) else None
    if not isinstance(paths, dict):
        return []
    out = []
    for p in paths:
        if isinstance(p, str) and p.startswith("/"):
            out.append(origin + p)
    return out


def _parse_doc_body(text, page_url, origin):
    """Extract (url, source-label) hits from one fetched doc page body.

    Covers REST (spec links + quoted paths), GraphQL, WebSocket (ws URLs),
    webhooks, SOAP (address + WSDL ops), gRPC (proto links / grpc paths).
    """
    hits = []
    low = text.lower()

    # 1. REST/OpenAPI request-body style: whole page IS a JSON spec.
    stripped = text.strip()
    if stripped[:1] == "{":
        for u in _extract_openapi_paths(stripped, origin):
            hits.append((u, "openapi"))

    # 2. Spec-file links inside the HTML (<a href="...openapi.yaml"> etc).
    for href in _DOC_SPEC_HREF_RE.findall(text):
        spec_url = urljoin(page_url, href)
        if not urlparse(spec_url).netloc:
            continue
        slow = spec_url.lower()
        if slow.endswith((".wsdl",)):
            hits.append((spec_url, "soap"))
        elif slow.endswith((".proto",)):
            hits.append((spec_url, "grpc"))
        else:
            hits.append((spec_url, "openapi"))

    # 3. Generic quoted REST-ish paths in the docs.
    for p in _DOC_API_PATH_RE.findall(text):
        p = p.strip()
        if not p or " " in p or "\\n" in p:
            continue
        hits.append((urljoin(origin, p), "rest-docs"))

    # 3b. Bare API resource paths in human-readable docs (<code> blocks,
    # "GET /api/v2/..." lines). Keeps query strings (?id=1&author=...).
    for p in _DOC_BARE_PATH_RE.findall(text):
        p = p.strip().rstrip(".,);:")
        if not p or " " in p or "\\n" in p:
            continue
        hits.append((urljoin(origin, p), "rest-docs"))

    # 4. GraphQL: endpoint refs + playground hints.
    if "graphql" in low:
        for p in re.findall(
            r"""["'`](/(?:graphql\w*(?:[A-Za-z0-9_\-./{}:$]*))?)["'`]""",
            text,
            re.I,
        ):
            if p and p.strip():
                hits.append((urljoin(origin, p.strip()), "graphql"))
        if "/graphql" not in [h[0].replace(origin, "") for h in hits]:
            hits.append((origin + "/graphql", "graphql"))

    # 5. WebSocket: literal ws(s):// URLs + /ws path refs.
    for w in _WS_URL_RE.findall(text):
        hits.append((w.strip(), "websocket"))
    if "websocket" in low or "socket.io" in low:
        for p in re.findall(
            r"""["'`](/(?:ws|socket\.?io|realtime)(?:[A-Za-z0-9_\-./{}:$]*))["'`]""",
            text,
            re.I,
        ):
            if p and p.strip():
                hits.append((urljoin(origin, p.strip()), "websocket"))

    # 6. Webhooks.
    for p in _WEBHOOK_PATH_RE.findall(text):
        if p and p.strip():
            hits.append((urljoin(origin, p.strip()), "webhook"))

    # 7. SOAP: <soap:address location> + operation names.
    for addr in _SOAP_ADDR_RE.findall(text):
        addr = addr.strip()
        if addr:
            hits.append((
                addr if urlparse(addr).netloc else urljoin(page_url, addr),
                "soap",
            ))
    if "wsdl" in low or "soap" in low:
        for op in _SOAP_OP_RE.findall(text):
            op = op.strip()
            if op and " " not in op:
                hits.append((urljoin(origin, "/soap/" + op), "soap"))
        for href in re.findall(
            r"""["'`]([^"'`#]*\?wsdl[^"'`]*)["'`]""", text, re.I
        ):
            if href.strip():
                hits.append((urljoin(page_url, href.strip()), "soap"))

    # 8. gRPC: .proto refs, grpc paths.
    if "grpc" in low or ".proto" in low:
        for p in re.findall(
            r"""["'`](/(?:grpc[A-Za-z0-9_\-./{}:$]*))["'`]""", text, re.I
        ):
            if p and p.strip():
                hits.append((urljoin(origin, p.strip()), "grpc"))

    return hits


def _docs_source(store, crawl_records, target_url, session):
    """Fetch doc pages found in the crawl (docs-first) + spec-location probe.

    Returns the number of distinct URLs added. GET only; errors skipped.
    """
    origin = _origin(target_url)
    before = len(store)
    pages = _doc_pages_from_crawl(crawl_records)

    # Landing pages that often RENDER the docs without a doc-ish URL
    # (e.g. GET /api returns the HTML route list). Only exact paths,
    # so real API endpoints are never re-fetched as docs.
    for record in crawl_records or []:
        if not isinstance(record, dict):
            continue
        u = record.get("url")
        if not isinstance(u, str) or not u:
            continue
        try:
            if urlparse(u.split("#")[0]).path.rstrip("/") in ("", "/api", "/docs"):
                clean = u.split("#")[0].strip()
                if clean and clean not in pages:
                    pages.append(clean)
        except (ValueError, UnicodeError):
            continue

    # Always probe the classic spec locations too (cheap, docs-driven).
    probe_urls = [origin + loc for loc in OPENAPI_LOCATIONS]
    for u in pages:
        if u not in probe_urls:
            probe_urls.append(u)

    for doc_url in probe_urls[: _MAX_DOC_PAGES + len(OPENAPI_LOCATIONS)]:
        try:
            r = session.get(
                doc_url, timeout=_TIMEOUT,
                headers={"Accept": "application/json, text/html, */*;q=0.8"},
            )
        except requests.RequestException:
            continue
        if r.status_code != 200:
            continue
        try:
            body = r.text[:_MAX_DOC_BYTES]
        except (ValueError, UnicodeError):
            continue
        if not body or not body.strip():
            continue
        ctype = (r.headers.get("Content-Type") or "").lower()
        is_spec = "swagger" in doc_url or "openapi" in doc_url or "api-docs" in doc_url
        if ("json" in ctype or is_spec) and body.strip()[:1] == "{":
            for u in _extract_openapi_paths(body, origin):
                label = "swagger" if "swagger" in doc_url else "openapi"
                _add(store, u, label)
            continue
        for url, label in _parse_doc_body(body, doc_url, origin):
            _add(store, url, label)

    return len(store) - before


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
    enable_docs=True,
    enable_common_paths=True,
    wordlist=None,
    extra_paths=None,
    verbose=False,
):
    """Multi-source discovery, docs-first. Always includes passive crawler source.

    `target_url` enables network sources (javascript/docs/common_path).
    Docs (REST/OpenAPI, GraphQL, gRPC, WebSocket, webhooks, SOAP) are
    fetched BEFORE the wordlist; the wordlist is a last-resort fallback.
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
                if enable_docs or enable_openapi:
                    # Docs-first: REST/OpenAPI, GraphQL, gRPC, WebSocket,
                    # webhooks, SOAP — before any brute-forcing.
                    _docs_source(store, crawl_records, target_url, session)
                if enable_common_paths:
                    # Fallback LAST: only brute-force the wordlist now.
                    wl = []
                    if wordlist:
                        wl += load_wordlist(wordlist)
                    if extra_paths:
                        wl += list(extra_paths)
                    _common_path_source(store, target_url, session, extra_paths=wl, verbose=verbose)
                if enable_docs or enable_openapi:
                    # Second docs pass: the wordlist often uncovers HTML
                    # doc pages (e.g. /api landing page) that weren't in
                    # the crawl. Parse those too so query-string routes
                    # (?author=, ?published=) listed on them are extracted.
                    enriched = list(crawl_records or []) + [
                        {"url": u} for u in store
                    ]
                    _docs_source(store, enriched, target_url, session)
            finally:
                session.close()
    return _finalize(store)
