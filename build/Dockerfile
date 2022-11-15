FROM golang:1.19 as builder
WORKDIR /tmp/builder



COPY go.mod ./go.mod
COPY go.sum ./go.sum
RUN  go mod download

COPY . ./
RUN CGO_ENABLED=0 GOOS=$(go env GOOS) GOARCH=$(go env GOARCH) go build -ldflags="-s -w" ./


FROM alpine:3.16.3

RUN rm -rf /var/cache/apk/*

ARG BIN_NAME="falcoctl"
COPY --from=builder /tmp/builder/${BIN_NAME} /usr/bin/${BIN_NAME}
RUN ln -s /usr/bin/${BIN_NAME} /usr/bin/falcoctl-bin

ENTRYPOINT [ "/usr/bin/falcoctl-bin" ]