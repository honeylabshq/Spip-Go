# Spip - Network Honeypot Sensor

Spip is a lightweight, low-interaction network honeypot sensor. It listens for arbitrary incoming TCP traffic (plain and TLS), captures what scanners and bots send, and logs each connection as structured JSON (ECS-shaped) for easy ingestion into your SIEM or data lake.

Spip sensors power [HoneyLabs](https://honeylabs.net), a free, queryable threat intelligence platform built on the data they capture. To see what Spip collects in practice, browse the live per-IP reports there or the [weekly threat report](https://honeylabs.net/blog) generated from the sensor network.

![ezgif-476608ae440271e4](https://github.com/user-attachments/assets/cc34b524-5283-4442-9dda-4f6720977f3d)


## Quick Start

**Prerequisites**
- Go 1.24.0 or later
- Linux with `iptables`
- Root access (required to apply the example iptables rules)

1) Build the agent
```bash
git clone https://github.com/honeylabshq/Spip-Go.git
cd Spip-Go
go build -o spip-agent ./cmd/spip-agent
```

2) (Optional) Use the interactive setup helper
```bash
sudo ./scripts/initial_setup.sh
```
This helper writes a `config.toml` (it prompts for a short `name` used in logs), can generate self-signed TLS keys, optionally configures Loom (URL, sensor_id, token, etc.), and optionally applies the PREROUTING iptables redirect used in examples below.

3) Create or edit `config.toml`
Minimal `config.toml`:
```toml
name = "spip-agent"
ip = "127.0.0.1"
port = 8080
```

Optional configuration keys:
- `cert_path` / `key_path` — enable TLS if both set; may be relative to the config file (the setup script writes relative paths so the config works from any working directory)
- **Log output:** `log_file` (local) and/or `[loom]` (remote). See [Log output](#log-output) below.
- `read_timeout_seconds` / `write_timeout_seconds` — connection timeouts
- `rate_limit_per_second` / `rate_limit_burst` — connection rate-limiting
- `community_id_seed` — optional 16-bit seed for Community ID v1 flow hashing (omit or `0` for default)

If these runtime tuning fields are omitted or set to `0`, Spip applies the following defaults:
- `read_timeout_seconds`: 30
- `write_timeout_seconds`: 10
- `rate_limit_per_second`: 20
- `rate_limit_burst`: 50000
4) Redirect incoming TCP to the agent (example, excluding SSH)
```bash
sudo iptables -t nat -F
sudo iptables -t nat -A PREROUTING -p tcp --dport 22 -j RETURN
sudo iptables -t nat -A PREROUTING -p tcp -j REDIRECT --to-port 8080
```

5) Run the agent
```bash
./spip-agent -config config.toml
```

## Log output

Spip writes ECS logs to a **single local destination** and can **optionally** send the same logs to a Loom server:

| Destination | Config | Behaviour |
|-------------|--------|-----------|
| **Local** | `log_file` | **Default:** omit or leave empty → **stdout**. Set to a path → that file. One of the two, always on. |
| **Loom** | `[loom]` with `enabled = true` | Optional. Same events are batched and POSTed to your Loom ingest URL in addition to local. |

So: local defaults to stdout; override with `log_file` for a file. Optionally add Loom on top. Both use the same ECS format.

- **Local only:** leave `log_file` commented/empty (stdout) or set it to a path.
- **Local + Loom:** set local as above and add a `[loom]` section with `url`, `sensor_id`, `token` (see [Loom](#loom-optional-log-shipping) below).

## Log format
Spip emits each connection as a single JSON object. The output is formatted to be ECS-compatible using only the fields Spip can provide (no ASN/geo enrichment). Typical fields produced include:
- `@timestamp` — RFC3339 timestamp for the event
- `event.id` — per-connection session identifier
- `observer.hostname` / `host.name` — agent `name` from config
- `source.ip`, `source.port` and `destination.ip`, `destination.port`
- `network.transport` — e.g. `tcp`
- `http.request.body` / `url.path` — when the payload clearly resembles HTTP
- `user_agent.original` — when available
- `event.summary` — raw payload for non-HTTP probes
- `event.original_payload_hex` — raw payload hex (always preserved)
- [Fingerprinting](#fingerprinting) (built-in) adds `network.community_id`, `tls.client.*`, `http.request.hash.ja4h`, `ssh.client.hash.hassh` when applicable.

Example (ECS-shaped) record produced by Spip:
```json
{
  "@timestamp": "2025-12-01T19:35:18.123Z",
  "event": {
    "id": "bd30cdc1-95b0-49aa-b8fe-e77230b6a04f",
    "summary": "BitTorrent protocol",
    "original_payload_hex": "426974546f7272656e742070726f746f636f6c",
    "ingested_by": "spip"
  },
  "observer": {"hostname": "spip-agent"},
  "host": {"name": "spip-agent"},
  "source": {"ip": "146.70.1.1", "port": 35882},
  "destination": {"ip": "146.190.1.1", "port": 6881},
  "network": {"transport": "tcp"}
}
```

Note: the agent only emits fields it can derive from the connection payload and metadata. Downstream systems can enrich these records (geo, ASN, etc.) if desired.

## Fingerprinting

Spip can add passive fingerprinting fields to each connection record (ECS-compatible, no change to payload capture):

- **Community ID** (`network.community_id`) — v1 flow hash of the 5-tuple (source/dest IP and port, protocol). When traffic is redirected via iptables, Spip uses the **original destination** (before REDIRECT) so the hash matches what other tools (e.g. Zeek, Suricata) would compute for the same flow.
- **TLS** — From the ClientHello: `tls.client.server_name` (SNI), `tls.client.supported_protocols` (ALPN list), `tls.client.hash.ja4` (JA4 fingerprint).
- **HTTP** — From the first request: `http.request.hash.ja4h` (JA4H).
- **SSH** — When the payload starts with `SSH-2.0-` and contains a KEXINIT: `ssh.client.hash.hassh` (Hassh).

All of these are additive; existing behaviour (local log, Loom, payload hex, HTTP parsing) is unchanged.

**References (for verification and attribution):**  
Community ID: [Corelight Community ID spec](https://github.com/corelight/community-id-spec).  
JA4 / JA4H: [FoxIO JA4](https://github.com/FoxIO-LLC/ja4).  
Hassh: [Salesforce HASSH](https://github.com/salesforce/hassh).  
TLS fingerprinting uses [github.com/psanford/tlsfingerprint](https://github.com/psanford/tlsfingerprint) (MIT).

## Loom (optional log shipping)

Part of [log output](#log-output): when `[loom]` has `enabled = true`, the same ECS records are also batched and POSTed to your Loom ingest URL. Required when enabled: `url`, `sensor_id`, `token`. Optional: `batch_size` (default 50), `flush_interval` (e.g. `"10s"`), `insecure_skip_verify` (for self-signed Loom certs). The exporter runs asynchronously and does not block the capture loop; failed POSTs are logged to stderr and the batch is dropped (fail-open).

## Project Structure
```
.
├── cmd/                 # Main application entry point
├── internal/            # Config, logging, network, TLS, fingerprinting, exporters (e.g. Loom)
├── pkg/                 # Linux socket helpers (SO_ORIGINAL_DST via syscall)
├── test/                # End-to-end test helpers
└── scripts/             # Utility scripts (including `initial_setup.sh`)
```

## Testing
Run unit tests with:
```bash
go test ./...
```

**End-to-end tests** require privileges to manipulate `iptables`. Run them via the script (from the repo root):
```bash
sudo -E ./scripts/run_e2e_tests.sh
```
The script sets up the environment and iptables. Alternatively use the container helper: `./scripts/run_e2e_in_container.sh`. E2E validates core behaviour (payload capture, source/destination, TLS detection, Loom batching, fingerprinting).

## Notes on HTTP parsing and deployment

Spip performs best-effort HTTP request detection from the captured payload. When the payload clearly resembles an HTTP request (valid request line plus basic headers or ALPN), the agent emits `http.*`, `url.path`, and `user_agent.original` fields. When it does not, Spip falls back to storing the payload in `event.summary` and always preserves the raw payload hex in `event.original_payload_hex`.

Because Spip reflects the source IP in its responses and accepts arbitrary inbound TCP traffic, it is intended for use as a honeypot-style sensor or edge collector in controlled/monitored environments, not on arbitrary user endpoints.
## Initial setup helper
Run the interactive helper from the repo root (requires root when applying iptables rules):
```bash
sudo ./scripts/initial_setup.sh
```
The script prompts for: a short `name` (written into `config.toml`, used in logs as `observer.hostname` / `host.name`), listen IP and port, optional self-signed TLS cert generation (paths are written relative to the config so they work from any directory), optional Loom configuration (URL, sensor_id, token, batch_size, flush_interval, TLS verify), log file path, and optional iptables PREROUTING redirect.

