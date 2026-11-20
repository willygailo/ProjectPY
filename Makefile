.PHONY: setup test cov lint format format-check typecheck check build clean

PYTHON ?= python3
VENV ?= .venv
VENV_BIN := $(VENV)/bin

setup:
	$(PYTHON) -m venv $(VENV)
	$(VENV_BIN)/python -m pip install --upgrade pip
	$(VENV_BIN)/pip install -e ".[dev]"

test:
	@if [ -d tests ] && [ -n "$$(find tests -name 'test_*.py' -print -quit)" ]; then \
		pytest -v; \
	else \
		PYTHONPATH=src $(PYTHON) -m s1shell doctor --no-color; \
	fi

cov:
	@if [ -d tests ] && [ -n "$$(find tests -name 'test_*.py' -print -quit)" ]; then \
		pytest --cov=s1shell --cov-report=term-missing; \
	else \
		PYTHONPATH=src $(PYTHON) -m s1shell doctor --no-color; \
	fi

lint:
	@if [ -d tests ]; then ruff check src tests; else ruff check src; fi

format:
	@if [ -d tests ]; then ruff format src tests; else ruff format src; fi

format-check:
	@if [ -d tests ]; then ruff format --check src tests; else ruff format --check src; fi

typecheck:
	mypy src

check: lint format-check typecheck test

build:
	$(PYTHON) -m build
	twine check dist/*

clean:
	rm -rf build dist *.egg-info src/*.egg-info .pytest_cache .mypy_cache .ruff_cache .coverage htmlcov
