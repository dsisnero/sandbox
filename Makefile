SHELL := /bin/sh
CRYSTAL_CACHE_DIR ?= $(PWD)/.crystal-cache

.PHONY: install update format lint test parity clean

install:
	shards install

update:
	shards update

format:
	CRYSTAL_CACHE_DIR=$(CRYSTAL_CACHE_DIR) crystal tool format --check src spec

lint:
	ameba src spec

test:
	CRYSTAL_CACHE_DIR=$(CRYSTAL_CACHE_DIR) crystal spec

parity:
	./scripts/check_inventory_clean.sh

clean:
	rm -rf .crystal-cache
