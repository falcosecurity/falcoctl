SHELL=/bin/bash -o pipefail
# Get the currently used golang install path (in GOPATH/bin, unless GOBIN is set)
ifeq (,$(shell go env GOBIN))
GOBIN=$(shell go env GOPATH)/bin
else
GOBIN=$(shell go env GOBIN)
endif

GO ?= go
DOCKER ?= docker

# version settings
RELEASE?=$(shell git rev-parse HEAD)
COMMIT?=$(shell git rev-parse HEAD)
BUILD_DATE?=$(shell date -u +'%Y-%m-%dT%H:%M:%SZ')
PROJECT?=github.com/falcosecurity/falcoctl

# todo(leogr): re-enable race when CLI tests can run with race enabled
TEST_FLAGS ?= -v -cover# -race

falcoctl:
	$(GO) build -ldflags \
    "-X '${PROJECT}/cmd/version.semVersion=${RELEASE}' \
    -X '${PROJECT}/cmd/version.gitCommit=${COMMIT}' \
    -X '${PROJECT}/cmd/version.buildDate=${BUILD_DATE}'" \
    -o falcoctl .

.PHONY: test
test:
	$(GO) vet ./...
	$(GO) test ${TEST_FLAGS} ./...

# Install gci if not available
.PHONY: gci
gci:
ifeq (, $(shell which gci))
	@go install github.com/daixiang0/gci@v0.11.1
GCI=$(GOBIN)/gci
else
GCI=$(shell which gci)
endif

# Install addlicense if not available
.PHONY: addlicense
addlicense:
ifeq (, $(shell which addlicense))
	@go install github.com/google/addlicense@v1.0.0
ADDLICENSE=$(GOBIN)/addlicense
else
ADDLICENSE=$(shell which addlicense)
endif

# Run go fmt against code and add the licence header
.PHONY: fmt
fmt: gci addlicense
	go mod tidy
	go fmt ./...
	find . -type f -name '*.go' -a -exec $(GCI) write -s standard -s default -s "prefix(github.com/falcosecurity/falcoctl)" {} \;
	find . -type f -name '*.go' -exec $(ADDLICENSE) -l apache -c "The Falco Authors" -y "$(shell date +%Y)" {} \;

# Install golangci-lint if not available
.PHONY: golangci-lint
golangci-lint:
ifeq (, $(shell which golangci-lint))
	@go install github.com/golangci/golangci-lint/cmd/golangci-lint@v1.52.2
GOLANGCILINT=$(GOBIN)/golangci-lint
else
GOLANGCILINT=$(shell which golangci-lint)
endif

# It works when called in a branch different than main.
# "--new-from-rev REV Show only new issues created after git revision REV"
.PHONY: lint
lint: golangci-lint
	$(GOLANGCILINT) run --new-from-rev main

.PHONY: docker
docker:
	$(DOCKER) build -f ./build/Dockerfile . --build-arg RELEASE=${RELEASE} --build-arg COMMIT=${COMMIT} --build-arg BUILD_DATE=${BUILD_DATE}

.PHONY: clean
clean:
	@rm falcoctl || true
