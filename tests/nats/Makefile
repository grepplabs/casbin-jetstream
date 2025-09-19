SHELL := /bin/bash
.SHELLFLAGS += -o pipefail -O extglob
.DEFAULT_GOAL := help

ROOT_DIR  := $(shell dirname $(realpath $(firstword $(MAKEFILE_LIST))))

CFSSL_DIR := $(ROOT_DIR)/cfssl
CERT_DIR := $(CFSSL_DIR)/certs

.PHONY: help
help: ## Display this help
	@printf "\nUsage:\n  make \033[36m<target>\033[0m\n"
	@awk 'BEGIN {FS = ":.*##";} \
		/^[a-zA-Z_0-9-]+:.*?##/ { \
			printf "  \033[36m%-35s\033[0m %s\n", $$1, $$2 } \
			/^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) \
		} ' \
	$(MAKEFILE_LIST)


.PHONY: create-certs
create-certs: ## Create NATS server and clients certificates
	cfssl genkey -initca $(CFSSL_DIR)/csr-root-ca.json | cfssljson -bare $(CERT_DIR)/ca

	cfssl gencert -ca=$(CERT_DIR)/ca.pem -ca-key=$(CERT_DIR)/ca-key.pem -config=$(CFSSL_DIR)/ca-config.json \
	  -profile=nats-server $(CFSSL_DIR)/csr-nats-server.json | cfssljson -bare $(CERT_DIR)/nats-server

	cfssl gencert -ca=$(CERT_DIR)/ca.pem -ca-key=$(CERT_DIR)/ca-key.pem -config=$(CFSSL_DIR)/ca-config.json \
	  -profile=nats-client $(CFSSL_DIR)/csr-nats-client.json | cfssljson -bare $(CERT_DIR)/nats-client