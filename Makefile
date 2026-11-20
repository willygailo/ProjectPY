.PHONY: setup test cov lint format format-check typecheck check build clean

PYTHON ?= python3
VENV ?= .venv
VENV_BIN := $(VENV)/bin

setup:
	$(PYTHON) -m venv $(VENV)
	$(VENV_BIN)/python -m pip install --upgrade pip
	$(VENV_BIN)/pip install -e ".[dev]"

test:
	pytest -v

cov:
	pytest --cov=s1shell --cov-report=term-missing

lint:
	ruff check src tests

format:
	ruff format src tests

format-check:
	ruff format --check src tests

typecheck:
	mypy src

check: lint format-check typecheck test

build:
	$(PYTHON) -m build
	twine check dist/*

clean:
	rm -rf build dist *.egg-info src/*.egg-info .pytest_cache .mypy_cache .ruff_cache .coverage htmlcov
