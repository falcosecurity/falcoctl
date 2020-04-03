SHELL=/bin/bash -o pipefail

GO ?= go

TEST_FLAGS ?= -v -race

.PHONY: falcoctl
falcoctl:
	$(GO) build .

.PHONY: test
test:
	$(GO) vet ./...
	$(GO) test ${TEST_FLAGS} ./...