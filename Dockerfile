FROM golang:1.20-bookworm as build
ARG GOARCH="amd64"

COPY . /build_dir
WORKDIR /build_dir
RUN go build -v .

FROM debian:stable-slim

RUN apt-get update && \
    apt-get -y install ca-certificates && \
    rm -rf /var/lib/apt/lists/*

COPY --from=build /build_dir/smtprelay /usr/local/bin/smtprelay
ENTRYPOINT ["/usr/local/bin/smtprelay"]
