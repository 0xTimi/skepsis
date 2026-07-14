.PHONY: help install lint format type test cov check docs clean demo

help:  ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-12s\033[0m %s\n", $$1, $$2}'

install:  ## Install the package with dev extras
	pip install -e '.[dev]'

lint:  ## Run ruff lint
	ruff check .

format:  ## Auto-format with ruff
	ruff format .
	ruff check --fix .

type:  ## Run mypy
	mypy src

test:  ## Run the test suite
	pytest

cov:  ## Run tests with an HTML coverage report
	pytest --cov-report=html
	@echo "open htmlcov/index.html"

check: lint type test  ## Run the full CI check locally

docs:  ## Serve the docs locally
	mkdocs serve

demo:  ## Run Skepsis against the bundled vulnerable library
	skepsis scan examples/vulnerable-canlib --panel mock

clean:  ## Remove build & cache artifacts
	rm -rf build dist *.egg-info site htmlcov .coverage coverage.xml
	find . -type d -name __pycache__ -exec rm -rf {} +
	rm -rf .pytest_cache .mypy_cache .ruff_cache
