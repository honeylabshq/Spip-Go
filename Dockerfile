FROM golang:1.24-bullseye

RUN apt-get update && apt-get install -y --no-install-recommends \
    iptables iproute2 procps ca-certificates git bash \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /work
COPY . /work

RUN go build -o spip-agent ./cmd/spip-agent || true
