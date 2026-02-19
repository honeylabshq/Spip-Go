#!/bin/bash

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "Please run with sudo -E to preserve environment"
    exit 1
fi

# Get the current user
SUDO_USER_HOME=$(eval echo ~$SUDO_USER)
export PATH=$PATH:$SUDO_USER_HOME/go/bin:/usr/local/go/bin

# Kill any existing spip-agent processes
echo "Cleaning up existing processes..."
pkill -f spip-agent || true

# Build the agent first as the regular user
echo "Building spip-agent..."
cd "$(dirname "$0")/.."
go build -o spip-agent ./cmd/spip-agent

if [ ! -f "./spip-agent" ]; then
    echo "Failed to build spip-agent"
    exit 1
fi

# Clean up any existing iptables rules
echo "Cleaning up iptables rules..."
iptables -t nat -F

# Run the tests (use the `e2e` build tag).
# E2E validates core behaviour (payload, source/dest, TLS, Loom). Fingerprinting adds extra ECS fields only.
echo "Running end-to-end tests with race detection..."
if [ -n "$1" ]; then
    echo "Running test: $1"
    go test -v -race -timeout 30s -tags=e2e ./test/e2e/... -run "$1"
else
    go test -v -race -timeout 30s -tags=e2e ./test/e2e/...
fi

# Clean up
echo "Cleaning up..."
iptables -t nat -F
rm -f spip-agent
pkill -f spip-agent || true

echo "Done!" 