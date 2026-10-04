# 🔍 API Endpoint Discovery

> Point it at a website. Get back every API hiding inside — what it returns, who can reach it, and the proof.

A small, readable pipeline built for learning how real API reconnaissance works:

```
┌────────────┐    ┌───────────────┐    ┌──────────────┐    ┌─────────────┐
│   Target   │───▶│    Crawler    │───▶│  Discovery   │───▶│  Analysis   │───▶ JSON
│    URL     │    │  breadth-first│    │  multi-source│    │ safe GETs,  │
│            │    │  same-domain  │    │  deduped     │    │ classified  │
└────────────┘    └───────────────┘    └──────────────┘    └─────────────┘
```

No heavy frameworks. No magic. Just `requests` + `BeautifulSoup` + clean heuristics you can read in an afternoon.

---

## ⚡ Quickstart

```bash
# 1. Set up (once)
python3 -m venv venv
source venv/bin/activate          # Windows: .\venv\Scripts\Activate.ps1
pip install -r requirements.txt   # includes flask, gunicorn, pyyaml, fpdf2

# 2a. Full pipeline via CLI
python crawler.py http://<TARGET-ADDRESS>/ --analyze

# 2b. Or via the live dashboard (recommended)
python app.py                     # open http://127.0.0.1:5000
# Windows: prefer the project venv — bare `python app.py` under system
# Python 500s on ?format=pdf when fpdf2 lives only in the venv:
.\venv\Scripts\python.exe app.py
```

Example: pages crawled → API candidates → verdicts like `confirmed`, `likely`, `public`. Counts depend on the target.

---

## 📖 Usage

```bash
# Crawl only — see what the spider finds
python crawler.py http://localhost:8000/

# Save the report to a file
python crawler.py http://localhost:8000/ --analyze -o results.json

# Keep big sites manageable (default: 50 pages)
python crawler.py https://example.com/ --analyze --max-pages 20

# Be polite — wait N seconds between requests so you don't hammer the site
python crawler.py https://example.com/ --analyze --delay 1

# Use the bundled 200-entry wordlist (opt-in, no default brute-forcing)
python crawler.py http://10.49.149.174/ --analyze --wordlist common_wordlist.txt -v

# Fuzz query params on API candidates (?id=1..N, boundaries 0/-1/99999/abc, bare-path ?id/?page/...)
python crawler.py http://localhost:8000/ --analyze --enum-ids 5

# Force a port (useful for bare IP/host targets, overrides any port in the URL)
python crawler.py 10.49.149.174 -p 8080 --analyze

# Try it against OWASP Juice Shop
python crawler.py http://localhost:3000/ --analyze -o results.json
```

| Flag | What it does |
|---|---|
| _(none)_ | Crawl + discover, print a short summary |
| `--analyze` | Probe each candidate and print the full JSON report |
| `-o FILE` | Write the report to `FILE` instead of stdout |
| `--max-pages N` | Stop crawling after `N` pages (default: 50) |
| `--delay SECONDS` | Wait N seconds between requests to avoid bombarding the site (default: 0) |
| `--wordlist FILE` | Extra wordlist file of any size (one path per line, `#` comments ignored); e.g. `--wordlist common_wordlist.txt`. Wordlist probing is opt-in only — no built-in default. |
| `--enum-ids N` | Fuzz query params: enumerate numeric values `1..N`, boundary/type probes (`0`, `-1`, `99999`, `abc`), probe common params on bare API endpoints. `0` disables (default: `0`). |
| `-p PORT`, `--port PORT` | Force port on target URL (e.g. `-p 8080`); overrides any port already in the URL. Useful for bare IP/host targets. |
| `-v` | Show each wordlist path as it is checked |

---

## 🕵️ How discovery works

One call — `discover_endpoints(crawl_records, target_url)` — fuses all sources docs-first, dedupes them, and tags every hit with *how* it was found (wordlist brute-forcing runs last, opt-in only):

| Source | Technique |
|---|---|
| `crawler` | Passive filter over crawled pages — `/api/`, `/v1/`, `/v2/`, `/graphql`, `/chat`, `/openai/`, `/logs`, `/resources/`, `.json` URLs, JSON content types |
| `javascript` | Fetches root HTML + up to 10 same-origin `<script src>` files, regexes API-ish strings. Nothing is executed |
| `openapi` / `swagger` | Probes known spec locations (`/swagger.json`, `/openapi.json`, `/api-docs`, …) and extracts `paths` keys |
| `rest-docs` / `graphql` / `grpc` / `websocket` / `webhook` / `soap` | Fetches doc pages found in the crawl plus default landing pages (`/api`, `/docs`, `/swagger`, `/graphql`, `/playground`, …), extracts quoted + bare (`<code>/api/…?id=1</code>`) routes, spec-file links, `ws(s)://` URLs, WSDL operations, `.proto` refs |
| `robots` / `sitemap` | Default cheap GETs: `/robots.txt` Disallow/Allow paths + `/sitemap.xml` `<loc>` URLs (same host only) |
| `common_path` | Opt-in wordlist only (no built-in default, GET only) — supply via `--wordlist common_wordlist.txt` (~200 entries) or `extra_paths=`; skipped silently when no wordlist is given |
| `param-fuzz` | Opt-in via `--enum-ids N`: numeric query enum `1..N`, boundary/type probes (`0`, `-1`, `99999`, `abc`), bare-path probes (`?id`, `?page`, `?limit`, `?offset`, `?user_id`, `?author`, `?published`). Year-like params skipped; non-numeric values never mutated |

Every candidate looks like this — so you always know *why* something was flagged:

```json
{"url": "http://localhost:8000/api/users.json", "source": "crawler", "sources": ["crawler", "javascript"]}
```

---

## 📊 What analysis tells you

Each endpoint gets one safe GET (sensitive query values are blanked before sending, redirects stay same-host, bodies are size-capped) and comes back with:

- **Basics** — `method`, `status`, `status_category`, `content_type`, `response_time_ms`, `response_size`, `final_url` + `redirect_chain`, selected headers (incl. `x-content-type-options`, `x-frame-options` observations)
- **Shape** — `parameters` (query + numeric/UUID path IDs), `response_structure` (inferred JSON keys/nested/item types; XML/SOAP element tree with RSS/Atom feed and SOAP-fault flags; `html` / `text` / `binary` / `empty` / `unknown`)
- **Verdict** — `api_behavior`: `confirmed` ✅ / `likely` / `uncertain` / `unlikely`, each with human-readable evidence, plus a plain-English `verdict` (`api`, `probably_api`, `web_page`, …) with a summary and suggested next step
- **Exposure** — `access`: `public` 🌐 / `authentication_required` / `forbidden` / `unknown`
- **Security posture** — missing-header issues (`missing_hsts`, `missing_csp`, CORS signals…), `sensitive_findings` (leaked secrets/tokens in responses)
- **Honesty** — `warnings` and per-endpoint `error` objects; one bad URL never kills the batch
- **OPTIONS probe** — on a 405 GET, one lightweight `OPTIONS` request follows (no redirects/body) to capture `Allow` methods for the verdict; recorded as `options_probe: {status, error}`. Disable with `EndpointAnalyzer(options_probe=False)`.

---

## ✅ Testing

```bash
pip install pytest                                  # not in requirements.txt (venv-only)
python -m pytest test_endpoint_discovery.py -q      # unit tests — pure mocks, no network needed
```

You can also analyse a saved discovery file directly:

```bash
python endpoint_analysis.py discovery.json analysis.json
```

---

## 🕷️ Crawler notes

- Follows `<a href>` links only (same-domain, breadth-first). Doc-looking pages (`swagger`, `graphql`, `webhook`, …) are queued first, docs-first.
- Slow targets get **one automatic retry on timeout** (VPN boxes and cold containers often drop the first attempt and answer the second). Other errors fail fast.
- Template-literal URLs (e.g. `` `/api/products/${id}/price` `` in inline scripts) are extracted, `${...}` is normalized to `1`, and appended as records so discovery flags them — they don't count against `--max-pages` and are never re-crawled for links.
- HTTP redirects are canonicalized: the **final** URL is recorded, so links that bounce to `/` don't create duplicate homepage entries. 404s are skipped; other HTTP/network errors are logged, never fatal.
- Fragment-only links (`page.html#menu` vs `page.html#`) are normalized (`#` stripped) before queuing/visiting, so anchors never create duplicate pages or extra requests.
- `-p/--port` forces the port on the target (bare IP/host friendly, IPv6-aware, overrides any port in the URL). `--delay` throttles between requests.
- Library hooks for live UIs: `crawl(..., on_page=cb, on_error=cb)` streams each fetched page and each skip (`{url, reason}`) as it happens. Both are optional and backward compatible.

## 🖥️ Dashboard

```bash
python app.py                                       # http://127.0.0.1:5000
# Production: Procfile runs gunicorn app:app --threads 8
```

Real-time SSE scan with per-scan numbering (`scan #1, #2, …` addressable as `/api/result/2`):

- **Scan options card** — Max pages (1–500, your input, no hardcoding), Enum IDs (`--enum-ids` passthrough, 0 = off).
- **Wordlist card** — paste paths, upload any `.txt` file of **any size** (path brute-forcing is uncapped — no truncation; note the separate fuzz caps below), Clear button, optional bundled `common_wordlist.txt`. Live "Probed N paths → M live" summary after discovery.
- **Parameter fuzzing card** (opt-in) — param name + numeric range (From/To shown only in range mode) or word list (up to 50 words kept exactly, spacing included; at most 100 variants total — these caps stay because variants multiply per endpoint). Variants stream in tagged `param-fuzz` and are analyzed like everything else.
- **Sites crawled / Endpoints found** — scrollable tables with live progress bar and phase narration (`Crawling…`, `Analyzing endpoint i/N…`); unreachable pages surface as a counter instead of vanishing silently. Re-scanning can never show the previous scan's rows (per-scan stream isolation + generation guards).
- **Endpoints table** — URL (clickable hyperlink), Source, Result badge with plain-language hover meanings, Status column; per-category counts, category dropdown filter, click-to-expand inline analysis with verdict, evidence, security posture, sensitive findings, OPTIONS data, parameters, full JSON, and a **Copy analysis** button. Dark/light toggle with persisted theme; link colors readable in both.
- **Reports** — Download button with **JSON / YAML / PDF** picker. The PDF carries the findings table (URL, status, content-type, behavior, access, source, verdict), verdict/source breakdowns, request counts, wall-clock duration, and per-endpoint details (evidence, shape, params, security issues, sensitive findings, methods, auth, warnings, errors, redirects).
- **Storage hygiene** — reports expire after 30 minutes (background sweeper purges them; stale links return `410 Gone`). `POST /api/scan` answers with `expires_in_seconds` so clients know the TTL up front.

### 🔌 Dashboard API

| Method & path | What it does |
|---|---|
| `POST /api/scan` | Start a scan (`url`, `max_pages`, `enum_ids`, `extra_paths`, `use_default_wordlist`, `fuzz`). Returns `{scan_id, scan_no, expires_in_seconds}` — scans are addressable by id *or* sequential number |
| `GET /api/stream/<id-or-no>` | Server-Sent Events: live pages, candidates, results, phase/progress, wordlist summary, `done` |
| `GET /api/result/<id-or-no>` | Full scan JSON (status, target, pages, candidates, results) |
| `GET /api/report/<id-or-no>?format=json\|yaml\|pdf` | Download the report as a file (`scan-<host>-<id>.json/.yaml/.pdf`) |

---

## 🚧 Known limitations

- The crawler follows `<a href>` links only — JS-rendered SPAs yield few pages (discovery's same-origin script scan compensates).
- Status-code probing trusts the server: catch-all hosts that return `200` for every path (SPA shells) produce false-positive candidates — analysis still classifies them `unlikely`, but they cost requests. No soft-404 shell filtering in this tree.
- Analysis is GET-first with one conditional `OPTIONS` probe on 405 — POST/PUT/DELETE endpoints are otherwise judged by their GET behavior.
- Template-literal extraction covers inline scripts only; external `<script src>` bundles aren't scanned for backtick URLs (discovery's `javascript` source still regexes them for quoted API strings, same-origin only).

---

*Built as a 4-person educational project: crawler → discovery → analysis → CLI/output.*
