"""Tests for endpoint_discovery.py using mock crawler data (no network)."""

from endpoint_discovery import discover_endpoints, is_api_candidate


def test_path_hints():
    records = [
        {"url": "http://x/api/users", "status": 200, "content_type": "text/html"},
        {"url": "http://x/api/v1/orders", "status": 200, "content_type": "text/html"},
        {"url": "http://x/api/v2/items", "status": 200, "content_type": "text/html"},
        {"url": "http://x/v1/search", "status": 200, "content_type": "text/html"},
        {"url": "http://x/v2/items", "status": 200, "content_type": "text/html"},
        {"url": "http://x/graphql", "status": 200, "content_type": "text/html"},
        {"url": "http://x/about.html", "status": 200, "content_type": "text/html"},
    ]
    got = [c["url"] for c in discover_endpoints(records)]
    assert got == [r["url"] for r in records[:6]], got


def test_content_type_json():
    assert is_api_candidate(
        {"url": "http://x/data", "status": 200, "content_type": "application/json"}
    )
    assert is_api_candidate(
        {
            "url": "http://x/data",
            "status": 200,
            "content_type": "application/vnd.api+json; charset=utf-8",
        }
    )
    assert not is_api_candidate(
        {"url": "http://x/page", "status": 200, "content_type": "text/html"}
    )


def test_json_suffix():
    got = discover_endpoints(
        [{"url": "http://x/openapi.json", "status": 200, "content_type": ""}]
    )
    assert [c["url"] for c in got] == ["http://x/openapi.json"]
    assert got[0]["source"] == "crawler"


def test_output_shape_and_dedupe():
    records = [
        {"url": "http://x/api/a", "status": 200, "content_type": "text/html"},
        {"url": "http://x/api/a", "status": 200, "content_type": "text/html"},
        {"url": "http://x/plain", "status": 200, "content_type": "text/html"},
    ]
    got = discover_endpoints(records)
    assert [c["url"] for c in got] == ["http://x/api/a"], got
    assert got[0]["source"] == "crawler"


def test_source_merging():
    from endpoint_discovery import _add, _finalize

    store = {}
    _add(store, "http://x/api/users", "javascript")
    _add(store, "http://x/api/users", "common_path")
    got = _finalize(store)
    assert got == [
        {
            "url": "http://x/api/users",
            "source": "javascript",
            "sources": ["javascript", "common_path"],
        }
    ], got


def test_js_extraction_static():
    from endpoint_discovery import _JS_API_RE

    js = 'fetch("/api/users"); axios.post(\'/api/login\'); x="/v1/orders"; y="not an api";'
    found = _JS_API_RE.findall(js)
    assert "/api/users" in found and "/api/login" in found and "/v1/orders" in found
