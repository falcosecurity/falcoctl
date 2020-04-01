SHELL=/bin/bash -o pipefail

GO ?= go

TEST_FLAGS ?= -v -race

.PHONY: falco-exporter
falco-exporter:
	$(GO) build .

.PHONY: test
test:
	$(GO) vet ./...
	$(GO) test ${TEST_FLAGS} ./...