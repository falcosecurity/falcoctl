SHELL=/bin/bash -o pipefail

GO ?= go

# todo(leogr): re-enable race when CLI tests can run with race enabled
TEST_FLAGS ?= -v # -race 

.PHONY: falcoctl
falcoctl:
	$(GO) build .

.PHONY: test
test:
	$(GO) vet ./...
	$(GO) test ${TEST_FLAGS} ./...