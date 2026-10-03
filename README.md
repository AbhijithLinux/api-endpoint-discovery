# 🔍 API Endpoint Discovery

> Point it at a website. Get back every API hiding inside — what it returns, who can reach it, and the proof.

A small, readable pipeline built for learning how real API reconnaissance works:

```
┌────────────┐    ┌───────────────┐    ┌──────────────┐    ┌─────────────┐
│   Target   │───▶│    Crawler    │───▶│  Discovery   │───▶│  Analysis   │───▶ JSON
│    URL     │    │  breadth-first│    │  4 sources,  │    │ safe GETs,  │
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

Expected: 11 pages crawled → 6 API candidates → a JSON report with classifications like `confirmed`, `likely`, `public`.

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

One call — `discover_endpoints(crawl_records, target_url)` — fuses four sources, dedupes them, and tags every hit with *how* it was found:

| Source | Technique |
|---|---|
| `crawler` | Passive filter over crawled pages — `/api/`, `/v1/`, `/v2/`, `/graphql`, `.json` URLs, JSON content types |
| `javascript` | Statically scans same-origin `<script>` files for API strings (`fetch`, `axios`, …). Nothing is executed |
| `openapi` / `swagger` | Probes known spec locations (`/openapi.json`, `/api-docs`, …) and extracts `paths` keys |
| `common_path` | Opt-in wordlist only (no built-in default, GET only) — supply via `--wordlist common_wordlist.txt` (200 entries) or `extra_paths=`; skipped silently when no wordlist is given |

Every candidate looks like this — so you always know *why* something was flagged:

```json
{"url": "http://localhost:8000/api/users.json", "source": "crawler", "sources": ["crawler", "javascript"]}
```

---

## 📊 What analysis tells you

Each endpoint gets one safe GET (sensitive query values are blanked before sending, redirects stay same-host, bodies are size-capped) and comes back with:

- **Basics** — `method`, `status`, `content_type`, `response_time_ms`, selected headers
- **Shape** — `parameters` (query + path IDs), `response_structure` (inferred JSON schema, pagination hints, data wrappers)
- **Verdict** — `api_behavior`: `confirmed` ✅ / `likely` / `uncertain` / `unlikely`, each with human-readable evidence
- **Exposure** — `access`: `public` 🌐 / `authentication_required` / `forbidden` / `unknown`
- **Honesty** — `warnings` and per-endpoint `error` objects; one bad URL never kills the batch

---

## ✅ Testing

```bash
python -m pytest test_endpoint_discovery.py -q      # unit tests — pure mocks, no network needed
```

---

## 🕷️ Crawler notes

- Template-literal URLs (e.g. `` `/api/products/${id}/price` `` in inline scripts) are extracted, `${...}` is normalized to `1`, and added as crawl records so discovery flags them.
- HTTP redirects are canonicalized: the **final** URL is recorded, so links that bounce to `/` don't create duplicate homepage entries.
- Fragment-only links (`page.html#menu` vs `page.html#`) are normalized (`#` stripped) before queuing/visiting, so anchors never create duplicate pages or extra requests.

---

## 🚧 Known limitations

- The crawler follows `<a href>` links only — JS-rendered SPAs yield few pages (discovery's script scan compensates).
- Analysis sends GET requests only — POST/PUT/DELETE endpoints are judged by their GET behavior.
- External `<script src>` bundles aren't parsed by the crawler for template literals yet — only inline scripts are.

---

*Built as a 4-person educational project: crawler → discovery → analysis → CLI/output.*
