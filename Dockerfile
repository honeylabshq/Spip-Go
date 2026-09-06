# Keep in step with the `go` directive in go.mod. This is the third place the
# Go version was written down and the only one CI does not build, so it drifted
# silently: go.mod required 1.25.0 while this still said 1.24.
FROM golang:1.25-bullseye

RUN apt-get update && apt-get install -y --no-install-recommends \
    iptables iproute2 procps ca-certificates git bash \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /work
COPY . /work

RUN go build -o spip-agent ./cmd/spip-agent || true
