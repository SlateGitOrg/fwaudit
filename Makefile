RUN := uv run --frozen
PY := $(RUN) python -u
COV_MIN := 90

.PHONY: help install fmt format-check lint typecheck test coverage check demo eval bench \
	fixtures golden pin-cvedb verify-cvedb clean

help: ## list targets
	@grep -E '^[a-z-]+:.*## ' $(MAKEFILE_LIST) | awk -F':.*## ' '{printf "  %-14s %s\n", $$1, $$2}'

install: ## create .venv from uv.lock
	uv sync --frozen

fmt: ## apply ruff formatting and safe lint fixes
	$(RUN) ruff format .
	$(RUN) ruff check --fix .

format-check: ## fail if any file is not ruff-formatted
	$(RUN) ruff format --check .

lint: ## ruff lint (zero warnings)
	$(RUN) ruff check .

typecheck: ## mypy --strict over src and scripts
	$(RUN) mypy

test: ## unit, integration, property and golden tests
	$(RUN) pytest

coverage: ## tests with branch coverage; fails below COV_MIN percent
	$(RUN) pytest --cov=fwaudit --cov-branch --cov-report=term --cov-fail-under=$(COV_MIN)

check: format-check lint typecheck coverage ## the single gate: format + lint + types + tests + coverage

demo: ## offline end-to-end demo on the bundled example images
	./scripts/demo.sh

eval: ## score detection against synthetic ground truth (dev, held-out, hostile)
	$(PY) scripts/evaluate.py --split dev --seeds 0-99 --out results/eval-dev.json
	$(PY) scripts/evaluate.py --split holdout --seeds 100-199 --out results/eval-holdout.json
	$(PY) scripts/evaluate.py --hostile --out results/eval-hostile.json

bench: ## throughput, per-layout audit time and bomb peak memory
	$(PY) scripts/bench.py --out results/bench.json

fixtures: ## regenerate the bundled example images in examples/firmware
	$(RUN) fwaudit synth examples/firmware --seeds 23 --hostile

golden: ## regenerate tests/golden after an intentional output change
	$(PY) scripts/update_golden.py

pin-cvedb: ## re-pin the CVE subset SHA-256 after a deliberate edit
	$(PY) scripts/pin_cvedb.py

verify-cvedb: ## cross-check the CVE subset against the live NVD API (network)
	$(PY) scripts/verify_cvedb.py

clean: ## remove build and cache output
	rm -rf build .pytest_cache .mypy_cache .ruff_cache .hypothesis .coverage htmlcov
