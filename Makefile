# Agentic Memory Fabric — common dev tasks
# Override interpreter: make test PYTHON=python3.12

PYTHON ?= python3
SRC_DIR := src
TESTS_DIR := tests

.PHONY: help test lint format clean clean-demo check

help:
	@echo "Targets:"
	@echo "  make test    - run unit tests (unittest)"
	@echo "  make lint    - syntax check (compileall) + ruff check if available (pip install ruff)"
	@echo "  make format  - ruff format src and tests (requires: pip install ruff)"
	@echo "  make clean   - remove __pycache__ and *.pyc"
	@echo "  make clean-demo - remove generated .amf-*.db demo databases"
	@echo "  make check   - lint then test"

test:
	$(PYTHON) -m unittest discover -s $(TESTS_DIR) -p "test_*.py" -v

lint:
	$(PYTHON) -m compileall -q $(SRC_DIR)
	@if $(PYTHON) -m ruff --version >/dev/null 2>&1; then \
		$(PYTHON) -m ruff check $(SRC_DIR) $(TESTS_DIR); \
	else \
		echo "ruff not installed; install for stricter lint: pip install ruff"; \
	fi

format:
	@$(PYTHON) -m ruff --version >/dev/null 2>&1 || (echo "install ruff: pip install ruff" && exit 1)
	$(PYTHON) -m ruff format $(SRC_DIR) $(TESTS_DIR)

clean-databases:
	find . -maxdepth 1 -type f -name '.amf-*.db' -delete

clean-python:
	find . -type d -name __pycache__ -prune -exec rm -rf {} +
	find . -type f -name '*.py[co]' -delete
	find . -type d -name .pytest_cache -prune -exec rm -rf {} +
	find . -type d -name .mypy_cache -prune -exec rm -rf {} +
	find . -type d -name .ruff_cache -prune -exec rm -rf {} +
	find . -type d -name .coverage -prune -exec rm -rf {} +
	find . -type d -name .coverage.* -prune -exec rm -rf {} +
	find . -type d -name .coverage.xml -prune -exec rm -rf {} +
	find . -type d -name .coverage.xml.gz -prune -exec rm -rf {} +
	find . -type d -name .coverage.xml.gz.base64 -prune -exec rm -rf {} +

clean: clean-databases clean-python

# Convenience alias for removing the SQLite demo databases created by examples/.
clean-demo: clean-databases

check: lint test
