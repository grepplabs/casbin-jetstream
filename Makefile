SHELL := /bin/bash
.SHELLFLAGS += -o pipefail -O extglob
.DEFAULT_GOAL := help

ROOT_DIR  := $(shell dirname $(realpath $(firstword $(MAKEFILE_LIST))))

.PHONY: help
help: ## Display this help
	@printf "\nUsage:\n  make \033[36m<target>\033[0m\n"
	@awk 'BEGIN {FS = ":.*##";} \
		/^[a-zA-Z_0-9-]+:.*?##/ { \
			printf "  \033[36m%-35s\033[0m %s\n", $$1, $$2 } \
			/^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) \
		} ' \
	$(MAKEFILE_LIST)


##@ Test targets

.PHONY: test
test: ## run tests
	go test -v -race -count=1 ./...

.PHONY: benchmark
benchmark: ## run benchmarks
	go test -bench=. -benchmem ./...

##@ Run targets

.PHONY: start-nats-server
start-nats-server: ## start NATS server
	docker compose -f tests/nats/docker-compose.yaml up -d --force-recreate --wait

.PHONY: stop-nats-server
stop-nats-server: ## stop NATS server
	docker compose -f tests/nats/docker-compose.yaml down --volumes

##@ Auxiliary targets

.PHONY: list-rules
list-rules: ## list all casbin rules in the NATS KV store
	@for key in $$(nats kv ls casbin_rules | grep -v '^No ' | awk '{print $$1}'); do \
	  echo "== $$key =="; \
	  nats kv get casbin_rules $$key; \
	done

.PHONY: list-keys
list-keys: ## list all keys in the NATS KV store
	nats kv ls casbin_rules

.PHONY: del-bucket
del-bucket: ## delete the casbin_rules bucket
	nats kv del casbin_rules