SOURCES=./src
TESTS=./tests

.PHONY: bandit format mypy pytest ruff

bandit:
	uv run bandit --recursive $(SOURCES)

format:
	uv run ruff format $(SOURCES) $(TESTS)

mypy:
	uv run mypy $(SOURCES) $(TESTS)

pytest:
	PYTHONPATH=./toolbox uv run pytest $(TESTS)

ruff:
	uv run ruff check --fix $(SOURCES) $(TESTS)
