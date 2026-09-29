"""endpoint_discovery.py — Abhijith's multi-source API endpoint discovery.

Sources (docs-first order — brute-force wordlist runs LAST as fallback):
  1. crawler      — passive filter over crawl() records (original MVP logic).
  2. javascript   — static inspection of <script> resources for API string refs.
  3. docs         — fetch API documentation pages found during the crawl
                    (REST/OpenAPI, GraphQL, gRPC, WebSocket, webhooks, SOAP)
                    and extract real endpoints from them. Includes the
                    classic spec-location probe (openapi/swagger) as fallback.
  4. common_path  — user-supplied wordlist only (GET only),
                    used only after docs (fallback). No built-in default.

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
from urllib.parse import quote, urljoin, urlparse

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

# No built-in default wordlist: common_path source runs only when the
# caller supplies `wordlist=` and/or `extra_paths=` (see discover_endpoints).
# Kept as an empty tuple for backward-compatible imports.
COMMON_API_PATHS: tuple[str, ...] = ()

# Default doc landing pages probed standalone (cheap GETs, no brute-force).
# These often RENDER the docs without a doc-ish crawled URL
# (e.g. GET /api returns the HTML route list). Wordlist brute-forcing
# stays opt-in via --wordlist FILE.
DEFAULT_DOC_PATHS = (
    "/api",
    "/api/",
    "/docs",
    "/docs/",
    "/api/docs",
    "/api-docs",
    "/redoc",
    "/swagger",
    "/swagger/",
    "/openapi",
    "/openapi/",
    "/graphql",
    "/graphiql",
    "/playground",
)

# Sitemap <loc> entries.
_SITEMAP_LOC_RE = re.compile(r"<loc>\s*([^<>\s]+)\s*</loc>", re.I)
_MAX_ROBOTS_SITEMAP_BYTES = 500_000

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
# Continuation of a query value after a raw space in human-readable docs,
# e.g. "?author=J.K. Rowling&published=2003" (stops at <, quotes, parens).
_CONTINUATION_RE = re.compile(r"((?: +[A-Za-z0-9_.&,=%+$-]+)+)")
# Query ending in a dotted abbreviation ("...author=J.K") — the next 1-2
# alpha words almost certainly continue the value (" Rowling").
_ABBREV_TAIL_RE = re.compile(r"\.[A-Za-z]+$")

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
    # Raw spaces in printed query values ("?author=J.K. Rowling") are
    # reconstructed and percent-encoded; a match followed by plain prose
    # ("?published=1993 (This query...)") is kept as-is.
    for m in _DOC_BARE_PATH_RE.finditer(text):
        raw = m.group(1).strip()
        p = raw.rstrip(".,);:")
        if not p or " " in p or "\\n" in p:
            continue
        if "?" in raw:
            cont = _CONTINUATION_RE.match(text, m.end(1))
            if cont:
                extra = cont.group(1)
                # Use the raw (dot-preserving) match here: a trailing "."
                # may belong to an abbreviation ("J.K."), not prose.
                base, _, q = raw.rstrip(",);:").partition("?")
                if "=" in extra or "&" in extra:
                    # More params follow the space (" Rowling&published=2003").
                    p = base + "?" + quote((q + extra).strip(), safe="=&%")
                elif _ABBREV_TAIL_RE.search(q.rstrip(".")):
                    # Abbrev value continues ("J.K." + " Rowling").
                    words = extra.split()
                    if 1 <= len(words) <= 2 and all(
                        re.fullmatch(r"[A-Za-z.]+", w) for w in words
                    ):
                        p = base + "?" + quote(
                            (q + " " + " ".join(words)).strip(), safe="=&%"
                        )
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


def _robots_sitemap_source(store, target_url, session):
    """Fetch /robots.txt + /sitemap.xml (default, cheap GETs).

    robots Disallow/Allow paths and sitemap <loc> URLs on the same host
    are added as candidates (sources "robots"/"sitemap"). Returns extra
    same-host page URLs to also parse as doc pages.
    """
    origin = _origin(target_url)
    host = urlparse(target_url).netloc
    extra_pages: list[str] = []

    def _same_host(u: str) -> bool:
        try:
            return urlparse(u).netloc == host
        except (ValueError, UnicodeError):
            return False

    sitemap_urls: list[str] = [origin + "/sitemap.xml"]
    try:
        r = session.get(origin + "/robots.txt", timeout=_TIMEOUT)
        body = r.text[:_MAX_ROBOTS_SITEMAP_BYTES] if r.status_code == 200 else ""
    except requests.RequestException:
        body = ""
    if body and body.strip():
        for line in body.splitlines():
            s = line.strip()
            if not s or s.startswith("#"):
                continue
            low = s.lower()
            if low.startswith(("disallow:", "allow:")):
                path = s.split(":", 1)[1].strip().split()[0] if ":" in s else ""
                if path.startswith("/") and not path.startswith("/*"):
                    u = origin + path.split("#")[0]
                    if _same_host(u):
                        _add(store, u, "robots")
                        extra_pages.append(u)
            elif low.startswith("sitemap:"):
                sm = s.split(":", 1)[1].strip().split()[0] if ":" in s else ""
                if sm and (sm.startswith("/") or _same_host(sm)):
                    u = sm if urlparse(sm).netloc else origin + sm
                    if _same_host(u) and u not in sitemap_urls:
                        sitemap_urls.append(u)

    for sm_url in sitemap_urls[:5]:
        try:
            r = session.get(sm_url, timeout=_TIMEOUT)
            xml = r.text[:_MAX_ROBOTS_SITEMAP_BYTES] if r.status_code == 200 else ""
        except requests.RequestException:
            continue
        if not xml or "<loc>" not in xml.lower():
            continue
        for loc in _SITEMAP_LOC_RE.findall(xml)[:200]:
            u = loc.strip().split("#")[0]
            if not u or not _same_host(u):
                continue
            _add(store, u, "sitemap")
            extra_pages.append(u)

    return list(dict.fromkeys(extra_pages))


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

    # Always probe the classic spec locations + default doc landing
    # pages too (cheap, docs-driven, standalone without wordlist).
    probe_urls = [origin + loc for loc in OPENAPI_LOCATIONS]
    for loc in DEFAULT_DOC_PATHS:
        u = origin + loc
        if u not in probe_urls:
            probe_urls.append(u)
    # robots.txt / sitemap.xml: default discovery surface.
    for u in _robots_sitemap_source(store, target_url, session):
        if u not in pages and u not in probe_urls:
            probe_urls.append(u)
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
    if not paths:
        print("  [wordlist] skipped: no wordlist supplied (--wordlist FILE)", flush=True)
        return
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


# Params probed on bare (query-less) API endpoints: ?id=1, ?page=1, ...
COMMON_PROBE_PARAMS = ("id", "page", "limit", "offset", "user_id", "author", "published")

# Year-like params are never numerically enumerated (1..N is junk there).
_YEAR_LIKE_PARAMS = ("year", "published", "birth", "birthyear", "yob")

# Benign boundary/type values appended for each numeric param
# (0, -1, huge, non-numeric) — error messages on these leak info.
BOUNDARY_VALUES = ("0", "-1", "99999", "abc")


def expand_param_variants(candidates, max_numeric=5, max_total=50,
                          probe_bare=True):
    """Fuzz query params across candidates. Three moves, all GET-safe:

    1. Numeric enum: any numeric param (?id=1, ?page=2, ?limit=10)
       -> 1..max_numeric (year-like params skipped).
    2. Boundary/type probes per numeric param: 0, -1, 99999, abc.
    3. Bare probing: query-less API-ish endpoints get COMMON_PROBE_PARAMS
       with value 1 (?id=1, ?page=1, ...) to test for hidden filtering.

    Non-numeric values (author names) are never mutated. Returns NEW
    candidate dicts (source "param-fuzz"); inputs untouched. Capped at
    max_total new URLs — pair with --delay on real targets.
    """
    from urllib.parse import parse_qsl, urlsplit, urlunsplit, urlencode

    seen = set()
    for c in candidates or []:
        u = c.get("url") if isinstance(c, dict) else None
        if isinstance(u, str):
            seen.add(u.split("#")[0])
    out = []

    def _emit(url):
        if url in seen or len(out) >= max_total:
            return False
        seen.add(url)
        out.append({
            "url": url, "source": "param-fuzz",
            "sources": ["param-fuzz"],
        })
        return len(out) >= max_total

    def _is_api_path(path):
        low = (path or "").lower()
        return any(h in low for h in (
            "/api/", "/v1/", "/v2/", "/v3/", "/rest/", "/graphql",
            "/resources/",
        ))

    for c in candidates or []:
        if not isinstance(c, dict) or not isinstance(c.get("url"), str):
            continue
        try:
            parts = urlsplit(c["url"].split("#")[0])
        except (ValueError, UnicodeError):
            continue
        if not parts.query:
            # Move 3: bare API endpoint -> probe common params (?id=1 ...).
            if probe_bare and _is_api_path(parts.path):
                for name in COMMON_PROBE_PARAMS:
                    new_url = urlunsplit((
                        parts.scheme, parts.netloc, parts.path,
                        urlencode([(name, "1")]), "",
                    ))
                    if _emit(new_url):
                        return out
            continue
        try:
            pairs = parse_qsl(parts.query, keep_blank_values=True)
        except (ValueError, UnicodeError):
            continue
        for name, value in pairs:
            if not value.isdigit():
                continue
            if name.lower() in _YEAR_LIKE_PARAMS:
                continue  # enumerating years 1..N is junk
            # Move 1: numeric range 1..max_numeric.
            for n in range(1, max_numeric + 1):
                if str(n) == value:
                    continue
                new_pairs = [
                    (k, str(n) if k == name else v) for k, v in pairs
                ]
                if _emit(urlunsplit((
                    parts.scheme, parts.netloc, parts.path,
                    urlencode(new_pairs), "",
                ))):
                    return out
            # Move 2: boundary/type probes (skip ones already covered).
            for b in BOUNDARY_VALUES:
                if b == value:
                    continue
                if b.isdigit() and 1 <= int(b) <= max_numeric:
                    continue  # already emitted by the range above
                new_pairs = [
                    (k, b if k == name else v) for k, v in pairs
                ]
                if _emit(urlunsplit((
                    parts.scheme, parts.netloc, parts.path,
                    urlencode(new_pairs), "",
                ))):
                    return out
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
                    # Wordlist runs only when explicitly supplied (--wordlist
                    # FILE or extra_paths=); there is no built-in default.
                    wl = []
                    if wordlist:
                        wl += load_wordlist(wordlist)
                    if extra_paths:
                        wl += list(extra_paths)
                    if wl:
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
