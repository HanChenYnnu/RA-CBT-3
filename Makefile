.PHONY: setup test lint fmt smoke all

setup:
	python -m pip install --upgrade pip
	python -m pip install -e ".[dev]"

lint:
	ruff check .

fmt:
	ruff format .

test:
	PYTHONPATH=. pytest -q

smoke:
	PYTHONPATH=. python -m scripts.smoke_run

all:
	PYTHONPATH=. python -m scripts.run_all
