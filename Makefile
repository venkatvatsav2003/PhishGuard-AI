.PHONY: all install analyze test clean docker

VERSION ?= 2.0.0

all: install

install:
	pip install pyyaml python-whois dnspython

analyze:
	./analyze.sh $(ARGS)

test:
	python3 -m pytest tests/ -v

clean:
	rm -rf reports/ *.pyc __pycache__ .pytest_cache

docker:
	docker build -t phishguard:$(VERSION) .
