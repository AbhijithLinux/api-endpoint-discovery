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

# 2. Serve the demo site (terminal 1)
make server                        # serves test_site/ on :8000

# 3. Run the full pipeline (terminal 2)
python crawler.py http://localhost:8000/ --analyze
```

Expected: 11 pages crawled → 6 API candidates → a JSON report with classifications like `confirmed`, `likely`, `public`.

---

## 📖 Usage

```bash
# Crawl only — see what the spider finds
python crawler.py http://localhost:8000/

# Full pipeline — print the analysis as JSON
python crawler.py http://localhost:8000/ --analyze

# Save the report to a file
python crawler.py http://localhost:8000/ --analyze -o results.json

# Keep big sites manageable (default: 50 pages)
python crawler.py https://example.com/ --analyze --max-pages 20

# Try it against OWASP Juice Shop
python crawler.py http://localhost:3000/ --analyze -o results.json
```

| Flag | What it does |
|---|---|
| _(none)_ | Crawl + discover, print a short summary |
| `--analyze` | Probe each candidate and print the full JSON report |
| `-o FILE` | Write the report to `FILE` instead of stdout |
| `--max-pages N` | Stop crawling after `N` pages (default: 50) |

---

## 🕵️ How discovery works

One call — `discover_endpoints(crawl_records, target_url)` — fuses four sources, dedupes them, and tags every hit with *how* it was found:

| Source | Technique |
|---|---|
| `crawler` | Passive filter over crawled pages — `/api/`, `/v1/`, `/v2/`, `/graphql`, `.json` URLs, JSON content types |
| `javascript` | Statically scans same-origin `<script>` files for API strings (`fetch`, `axios`, …). Nothing is executed |
| `openapi` / `swagger` | Probes known spec locations (`/openapi.json`, `/api-docs`, …) and extracts `paths` keys |
| `common_path` | A tight 14-entry wordlist (`/api/users`, `/graphql`, …) checked with GET only |

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
make test      # unit tests — pure mocks, no network needed
```

---

## 🚧 Known limitations

- The crawler follows `<a href>` links only — JS-rendered SPAs yield few pages (discovery's script scan compensates).
- Discovery is heuristic, not exhaustive — no recursive fuzzing, no giant wordlists.
- Analysis sends GET requests only — POST/PUT/DELETE endpoints are judged by their GET behavior.
- Dynamically built URLs (e.g. `` `/api/products/${id}/price` `` template literals) aren't extracted yet.

---

*Built as a 4-person educational project: crawler → discovery → analysis → CLI/output.*
