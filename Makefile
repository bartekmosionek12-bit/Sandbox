.PHONY: install poc test dashboard image demo clean

install:
	python3 -m pip install -r requirements.txt

poc:
	python3 -m poc.build_poc

test:
	python3 -m pytest tests/ -q

image:
	docker build -t pickle-sandbox-detoner:latest -f docker/Dockerfile .

dashboard: poc
	python3 -m app.server

# Szybkie sprawdzenie kontrastu w terminalu: zly plik vs czysty.
demo: poc
	@echo "=== ZLOSLIWY ==="
	@python3 -m sandbox_rce.pipeline poc/samples/evil_os_system.pkl | python3 -c \
		"import json,sys; d=json.load(sys.stdin); print('werdykt:', d['final_verdict'], '|', d['verdict_source']); print('zdarzenia:', len(d['sandbox']['events']))"
	@echo "=== CZYSTY ==="
	@python3 -m sandbox_rce.pipeline poc/samples/clean_model.pkl | python3 -c \
		"import json,sys; d=json.load(sys.stdin); print('werdykt:', d['final_verdict'], '|', d['verdict_source']); print('zdarzenia:', len(d['sandbox']['events']))"

clean:
	rm -rf poc/samples/*.pkl __pycache__ */__pycache__ .pytest_cache
