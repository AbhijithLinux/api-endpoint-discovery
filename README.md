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
pip install -r requirements.txt

# 2. Run the full pipeline (terminal 2)
python crawler.py http://<TARGET-ADDRESS>/ --analyze
```

Example: pages crawled → API candidates → a JSON report with classifications like `confirmed`, `likely`, `public`. Counts depend on the target.

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
| `--wordlist FILE` | Extra wordlist file (one path per line, `#` comments ignored); e.g. `--wordlist common_wordlist.txt`. Wordlist probing is opt-in only — no built-in default. |
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

- **Basics** — `method`, `status`, `status_category`, `content_type`, `response_time_ms`, `response_size`, `final_url` + `redirect_chain`, selected headers
- **Shape** — `parameters` (query + numeric/UUID path IDs), `response_structure` (inferred JSON keys/nested/item types; XML/SOAP element tree with RSS/Atom feed and SOAP-fault flags; `html` / `text` / `binary` / `empty` / `unknown`)
- **Verdict** — `api_behavior`: `confirmed` ✅ / `likely` / `uncertain` / `unlikely`, each with human-readable evidence
- **Exposure** — `access`: `public` 🌐 / `authentication_required` / `forbidden` / `unknown`
- **Honesty** — `warnings` and per-endpoint `error` objects; one bad URL never kills the batch

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
- Template-literal URLs (e.g. `` `/api/products/${id}/price` `` in inline scripts) are extracted, `${...}` is normalized to `1`, and appended as records so discovery flags them — they don't count against `--max-pages` and are never re-crawled for links.
- HTTP redirects are canonicalized: the **final** URL is recorded, so links that bounce to `/` don't create duplicate homepage entries. 404s are skipped; other HTTP/network errors are logged, never fatal.
- Fragment-only links (`page.html#menu` vs `page.html#`) are normalized (`#` stripped) before queuing/visiting, so anchors never create duplicate pages or extra requests.
- `-p/--port` forces the port on the target (bare IP/host friendly, IPv6-aware, overrides any port in the URL). `--delay` throttles between requests.

## 🖥️ Dashboard

```bash
python app.py                                       # http://127.0.0.1:5000
# Production: Procfile runs gunicorn app:app --threads 8
```

Real-time SSE scan: sites-crawled + endpoints-found scroll boxes, click an endpoint to expand its analysis (status, content-type, evidence, parameters, full JSON). Dark/light toggle. Note: the dashboard runs `crawl(max_pages=50)` → discover → analyze with defaults — no `--wordlist` / `--enum-ids` passthrough (use the CLI for those).

---

## 🚧 Known limitations

- The crawler follows `<a href>` links only — JS-rendered SPAs yield few pages (discovery's same-origin script scan compensates).
- Analysis sends GET requests only — POST/PUT/DELETE endpoints are judged by their GET behavior.
- Template-literal extraction covers inline scripts only; external `<script src>` bundles aren't scanned for backtick URLs (discovery's `javascript` source still regexes them for quoted API strings, same-origin only).

---

*Built as a 4-person educational project: crawler → discovery → analysis → CLI/output.*
