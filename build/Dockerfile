FROM golang:1.21 as builder
WORKDIR /tmp/builder

ARG RELEASE
ARG COMMIT
ARG BUILD_DATE
ARG PROJECT=github.com/falcosecurity/falcoctl

RUN test -n "$RELEASE" || ( echo "The RELEASE argument is unset. Aborting" && false )
RUN test -n "$COMMIT" || ( echo "The COMMIT argument is unset. Aborting" && false )
RUN test -n "$BUILD_DATE" || ( echo "The BUILD_DATE argument is unset. Aborting" && false )

COPY go.mod ./go.mod
COPY go.sum ./go.sum
RUN  go mod download

COPY . ./

RUN CGO_ENABLED=0 \
    GOOS=$(go env GOOS) \
    GOARCH=$(go env GOARCH) \
    go build -ldflags \
    "-s \
    -w \
    -X '${PROJECT}/cmd/version.semVersion=${RELEASE}' \
    -X '${PROJECT}/cmd/version.gitCommit=${COMMIT}' \
    -X '${PROJECT}/cmd/version.buildDate=${BUILD_DATE}'" \
    ./

RUN echo ${RELEASE}

FROM alpine:3.18.4

RUN apk update --no-cache && \
    apk add --upgrade --no-cache libssl3 libcrypto3
RUN rm -rf /var/cache/apk/*

ARG BIN_NAME="falcoctl"
COPY --from=builder /tmp/builder/${BIN_NAME} /usr/bin/${BIN_NAME}
RUN ln -s /usr/bin/${BIN_NAME} /usr/bin/falcoctl-bin

ENTRYPOINT [ "/usr/bin/falcoctl-bin" ]
