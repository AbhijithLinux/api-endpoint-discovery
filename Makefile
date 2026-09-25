PY := ./venv/bin/python
URL ?= http://localhost:8000/

.PHONY: server crawl discover analyze test

server:
	python -m http.server -d test_site 8000

crawl:
	$(PY) crawler.py $(URL)

discover:
	$(PY) -c "from crawler import crawl; from endpoint_discovery import discover_endpoints; import json; print(json.dumps(discover_endpoints(crawl('$(URL)'), target_url='$(URL)'), indent=2))"

analyze:
	$(PY) crawler.py $(URL) --analyze

test:
	$(PY) -c "import test_endpoint_discovery as t; t.test_path_hints(); t.test_content_type_json(); t.test_json_suffix(); t.test_output_shape_and_dedupe(); t.test_source_merging(); t.test_js_extraction_static(); print('All 6 discovery tests passed')"
