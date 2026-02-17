.PHONY: venv install test run-sim run-live lint-compile docker-build

venv:
	python3 -m venv .venv

install:
	. .venv/bin/activate && pip install -r requirements.txt

test:
	. .venv/bin/activate && pytest -q

lint-compile:
	. .venv/bin/activate && python -m py_compile run.py wsgi.py netsentinel/*.py

run-sim:
	. .venv/bin/activate && python run.py --mode simulation --port 5050

run-live:
	. .venv/bin/activate && sudo python run.py --mode live --interface en0 --port 5050

docker-build:
	docker build -t netsentinel:local .
