import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse


def fetch_page(url):
    response = requests.get(url, timeout=5)

    print("Status:", response.status_code)

    response.raise_for_status()

    content_type = response.headers.get("Content-Type", "")

    return response.text, response.status_code, content_type


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


def crawl(start_url, max_pages=50):

    domain = urlparse(start_url).netloc

    visited = set()
    seen = set([start_url])
    queue = [start_url]
    results = []

    while queue:

        if len(results) >= max_pages:
            print(f"Reached max pages ({max_pages}), stopping.")
            break

        url = queue.pop(0)

        if url in visited:
            continue

        print("\nCrawling:", url)

        try:

            html, status, content_type = fetch_page(url)

            visited.add(url)
            results.append(
                {"url": url, "status": status, "content_type": content_type}
            )

            links = extract_links(html, url)

            for link in links:

                if (
                    is_allowed(link, domain)
                    and link not in visited
                    and link not in seen
                ):
                    seen.add(link)
                    queue.append(link)

        except requests.HTTPError as e:

            if e.response is not None and e.response.status_code == 404:
                print(f"Skipping 404: {url}")
            else:
                print("HTTP Error:", e)

        except requests.RequestException as e:

            print("Error:", e)

    return results


if __name__ == "__main__":
    import argparse
    import json

    parser = argparse.ArgumentParser(description="Crawl a site and discover API endpoints.")
    parser.add_argument("url", nargs="?", help="Target URL (e.g. http://localhost:8000/)")
    parser.add_argument("--analyze", action="store_true", help="Run endpoint analysis on discovered candidates")
    parser.add_argument("-o", "--output", default=None, help="Write analysis JSON to file")
    parser.add_argument("--max-pages", type=int, default=50, help="Max pages to crawl (default: 50)")
    parser.add_argument("--wordlist", default=None, help="Extra wordlist file (one path per line, #comments ignored)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Show each wordlist path as it is checked")
    args = parser.parse_args()

    start_url = args.url or input("Enter start URL: ").strip()

    if not start_url:
        print("No URL provided. Usage: python crawler.py <start_url> [--analyze] [-o out.json]")
        raise SystemExit(1)

    if not start_url.startswith(("http://", "https://")):
        start_url = "http://" + start_url

    records = crawl(start_url, max_pages=args.max_pages)

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
