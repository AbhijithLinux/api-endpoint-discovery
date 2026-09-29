import re
import time

import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse

# Template-literal URL extraction (e.g. `/api/products/${id}/price`).
# Scans backtick blocks in raw HTML (inline scripts) for API-ish paths,
# normalizes ${...} interpolations to "1", and resolves them to absolute URLs.
# Synthetic records are appended to crawl() output so the passive crawler
# source in endpoint_discovery picks them up — no other module changes needed.
_TEMPLATE_BLOCK_RE = re.compile(r"`([^`]{0,2000})`")
_TEMPLATE_PATH_RE = re.compile(
    r"/(?:api|v1|v2|rest|graphql)(?:[A-Za-z0-9_\-./{}:$]*)",
    re.IGNORECASE,
)
_INTERPOLATION_RE = re.compile(r"\$\{[^}]*\}")
_JS_HINTS = ("/api", "/v1/", "/v2/", "/rest/", "/graphql")


def fetch_page(url):
    response = requests.get(url, timeout=5)

    print("Status:", response.status_code)

    response.raise_for_status()

    content_type = response.headers.get("Content-Type", "")

    # response.url is the FINAL url after requests followed any HTTP
    # redirects. Callers must use it — otherwise a page that redirects to
    # "/" is recorded under its original URL and the homepage gets
    # re-crawled under N different names.
    return response.text, response.status_code, content_type, response.url


def extract_links(html, current_url):
    soup = BeautifulSoup(html, "html.parser")

    links = []

    for link in soup.find_all("a"):

        href = link.get("href")

        if href:
            full_url = urljoin(current_url, href)
            links.append(full_url)

    return links


def is_allowed(url, domain):
    return urlparse(url).netloc == domain


def extract_template_literal_urls(html, current_url):
    """Extract API-ish URLs from JS template literals (backtick strings).

    `/api/products/${id}/price` -> `<origin>/api/products/1/price`.
    Returns a deduplicated list of absolute URLs.
    """
    if not html or "`" not in html:
        return []
    found = []
    seen_paths = set()
    for block in _TEMPLATE_BLOCK_RE.findall(html or ""):
        if "${" not in block and "/api" not in block.lower():
            # Fast skip: not a dynamic URL and no API hint at all.
            # Still allow v1/v2/rest/graphql blocks through below.
            low = block.lower()
            if not any(h in low for h in ("/v1/", "/v2/", "/rest/", "/graphql")):
                continue
        for raw_path in _TEMPLATE_PATH_RE.findall(block):
            path = _INTERPOLATION_RE.sub("1", raw_path).strip()
            if not path or " " in path or "\\n" in path:
                continue
            low = path.lower()
            if not any(h in low for h in _JS_HINTS):
                continue
            if path in seen_paths:
                continue
            seen_paths.add(path)
            try:
                full_url = urljoin(current_url, path.split("#")[0].strip())
            except (ValueError, UnicodeError):
                continue
            if not full_url or not urlparse(full_url).netloc:
                continue
            found.append(full_url)
    # Preserve order, dedupe.
    return list(dict.fromkeys(found))


def crawl(start_url, max_pages=50, delay=0.0):

    domain = urlparse(start_url).netloc

    try:
        delay = float(delay or 0.0)
    except (TypeError, ValueError):
        raise ValueError("--delay must be a number >= 0")
    if delay < 0:
        raise ValueError("--delay must be >= 0")

    visited = set()
    seen = set([start_url])
    queue = [start_url]
    results = []
    template_hits = []  # synthetic URLs from template literals (appended post-loop)
    template_seen = set()
    last_request_end = None

    while queue:

        if max_pages is not None and len(results) >= max_pages:
            print(f"Reached max pages ({max_pages}), stopping.")
            break

        url = queue.pop(0)

        if url in visited:
            continue

        print("\nCrawling:", url)

        # Politeness throttle: enforce at least `delay` seconds between
        # the end of the last request and the start of the next one.
        if delay > 0 and last_request_end is not None:
            elapsed = time.monotonic() - last_request_end
            if elapsed < delay:
                time.sleep(delay - elapsed)

        try:

            html, status, content_type, final_url = fetch_page(url)

            # Follow HTTP redirects properly: record the FINAL url, not the
            # requested one. Without this, every URL that bounces to the
            # homepage is stored under its old name and the homepage body
            # gets re-parsed N times (link stays "the same", content is "/").
            final_url = (final_url or url).split("#")[0]
            if final_url != url:
                print(f"Redirected: {url} -> {final_url}")
            visited.add(url)
            if final_url != url:
                if final_url in visited:
                    continue  # already crawled via its canonical URL
                visited.add(final_url)
            canon = final_url
            results.append(
                {"url": canon, "status": status, "content_type": content_type}
            )

            links = extract_links(html, canon)

            for link in links:
                if (
                    is_allowed(link, domain)
                    and link not in visited
                    and link not in seen
                ):
                    seen.add(link)
                    queue.append(link)

            # Template-literal extraction: collect only, append after the
            # loop so max_pages (real pages) semantics stay unchanged.
            try:
                for hit in extract_template_literal_urls(html, canon):
                    if hit not in visited and hit not in template_seen:
                        template_seen.add(hit)
                        template_hits.append(hit)
            except (ValueError, UnicodeError, TypeError):
                pass

        except requests.HTTPError as e:

            if e.response is not None and e.response.status_code == 404:
                print(f"Skipping 404: {url}")
            else:
                print("HTTP Error:", e)

        except requests.RequestException as e:

            print("Error:", e)

        finally:
            last_request_end = time.monotonic()

    # Append synthetic template-literal records so discovery's passive
    # crawler source flags them. Real-page budget (max_pages) is unaffected
    # since this happens after the loop.
    existing = {r.get("url") for r in results if isinstance(r, dict)}
    for hit in template_hits:
        if hit not in existing:
            existing.add(hit)
            results.append(
                {"url": hit, "status": 200, "content_type": "text/html"}
            )

    return results


if __name__ == "__main__":
    import argparse
    import json

    parser = argparse.ArgumentParser(description="Crawl a site and discover API endpoints.")
    parser.add_argument("url", nargs="?", help="Target URL (e.g. http://localhost:8000/)")
    parser.add_argument("--analyze", action="store_true", help="Run endpoint analysis on discovered candidates")
    parser.add_argument("-o", "--output", default=None, help="Write analysis JSON to file")
    parser.add_argument("--max-pages", type=int, default=50, help="Max pages to crawl (default: 50)")
    parser.add_argument("--delay", type=float, default=0.0, help="Seconds to wait between requests to avoid bombarding the site (default: 0)")
    parser.add_argument("--wordlist", default=None, help="Extra wordlist file (one path per line, #comments ignored)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Show each wordlist path as it is checked")
    args = parser.parse_args()

    start_url = args.url or input("Enter start URL: ").strip()

    if not start_url:
        print("No URL provided. Usage: python crawler.py <start_url> [--analyze] [-o out.json]")
        raise SystemExit(1)

    if not start_url.startswith(("http://", "https://")):
        start_url = "http://" + start_url

    records = crawl(start_url, max_pages=args.max_pages, delay=args.delay)

    print("\nFinished!")
    print("Pages visited:", len(records))

    try:
        from endpoint_discovery import discover_endpoints

        candidates = discover_endpoints(records, target_url=start_url, wordlist=args.wordlist, verbose=args.verbose)
        print(f"API candidates: {len(candidates)}")
        for candidate in candidates:
            print(f"  - {candidate['url']}")
    except ImportError:
        candidates = []

    if args.analyze:
        try:
            from endpoint_analysis import EndpointAnalyzer
        except ImportError:
            print("endpoint_analysis.py not found, skipping analysis.")
            raise SystemExit(1)
        with EndpointAnalyzer() as analyzer:
            analysis = analyzer.analyze_candidates(candidates)
        if args.output:
            with open(args.output, "w", encoding="utf-8") as f:
                json.dump(analysis, f, indent=2)
            print(f"Analysis written to {args.output}")
        else:
            print(json.dumps(analysis, indent=2))
