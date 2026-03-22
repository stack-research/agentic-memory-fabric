# Agentic Memory Fabric — common dev tasks
# Override interpreter: make test PYTHON=python3.12

PYTHON ?= python3
SRC_DIR := src
TESTS_DIR := tests

.PHONY: help test lint format clean check

help:
	@echo "Targets:"
	@echo "  make test    - run unit tests (unittest)"
	@echo "  make lint    - syntax check (compileall) + ruff check if available (pip install ruff)"
	@echo "  make format  - ruff format src and tests (requires: pip install ruff)"
	@echo "  make clean   - remove __pycache__ and *.pyc"
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

clean:
	find . -type d -name __pycache__ -prune -exec rm -rf {} +
	find . -type f -name '*.py[co]' -delete

check: lint test
