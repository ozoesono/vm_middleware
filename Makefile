.PHONY: install test db-up db-down db-migrate db-rollback run-pipeline lint clean

PYTHON ?= python3.12
VENV = .venv
PIP = $(VENV)/bin/pip
PYTEST = $(VENV)/bin/pytest
ALEMBIC = $(VENV)/bin/alembic

install:
	$(PYTHON) -m venv $(VENV)
	$(PIP) install --upgrade pip
	$(PIP) install -e ".[dev]"

test:
	$(PYTEST) tests/ -v --tb=short

test-cov:
	$(PYTEST) tests/ -v --tb=short --cov=src --cov-report=term-missing

db-up:
	docker-compose up -d postgres
	@echo "Waiting for PostgreSQL..."
	@sleep 3
	@echo "PostgreSQL is ready on localhost:5432"

db-down:
	docker-compose down

db-migrate:
	cd db && $(ALEMBIC) upgrade head

db-rollback:
	cd db && $(ALEMBIC) downgrade -1

db-revision:
	cd db && $(ALEMBIC) revision --autogenerate -m "$(msg)"

run-pipeline:
	$(VENV)/bin/python scripts/run_local.py

run-pipeline-mock:
	$(VENV)/bin/python scripts/run_local.py --mock

lint:
	$(VENV)/bin/ruff check src/ tests/
	$(VENV)/bin/ruff format --check src/ tests/

format:
	$(VENV)/bin/ruff check --fix src/ tests/
	$(VENV)/bin/ruff format src/ tests/

clean:
	rm -rf $(VENV) __pycache__ .pytest_cache .ruff_cache *.egg-info
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
