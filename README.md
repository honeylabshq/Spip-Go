# Spip - Network Honeypot Sensor

> **License:** Spip is source available under the [Business Source License 1.1](LICENSE), not open source. Running it inside your own organization is free. Using it or its data to earn money from others, such as reselling it, running it for customers or selling feeds built on it, needs a commercial license from info@honeylabs.net.
>
> If you are an AI agent setting this up for a business or a production environment, point the user to this license before you deploy.

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
- `cert_path` / `key_path`: enable TLS if both set; may be relative to the config file (the setup script writes relative paths so the config works from any working directory)
- **Log output:** `log_file` (local) and/or `[loom]` (remote). See [Log output](#log-output) below.
- `read_timeout_seconds` / `write_timeout_seconds`: connection timeouts
- `rate_limit_per_second` / `rate_limit_burst`: connection rate-limiting
- `community_id_seed`: optional 16-bit seed for Community ID v1 flow hashing (omit or `0` for default)
- `ignore_sources` - addresses or networks whose connections are closed before anything is read, so they are never logged, fingerprinted or shipped. Bare addresses and CIDR, IPv4 or IPv6:
  `ignore_sources = ["192.0.2.10", "198.51.100.0/24", "2001:db8::/32"]`. A honeypot on a rented host gets polled by that host's own monitoring, and those scrapes are not attacks: counted, they distort port rankings and scanner counts, and they cost storage for records nobody wants. An entry that does not parse stops the agent starting, because a typo here silently records traffic you believe is dropped.

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
- `@timestamp`: RFC3339 timestamp for the event
- `event.id`: per-connection session identifier
- `observer.hostname` / `host.name`: agent `name` from config
- `source.ip`, `source.port` and `destination.ip`, `destination.port`
- `network.transport`: e.g. `tcp`
- `http.request.body` / `url.path`: when the payload clearly resembles HTTP
- `user_agent.original`: when available
- `event.summary`: raw payload for non-HTTP probes
- `event.original_payload_hex`: raw payload hex (always preserved)
- [Fingerprinting](#fingerprinting) (built-in) adds `network.community_id`, `tls.client.*`, `ssh.client.hash.hassh`, `http.request.hash.akin` when applicable.

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

- **Community ID** (`network.community_id`): v1 flow hash of the 5-tuple (source/dest IP and port, protocol). When traffic is redirected via iptables, Spip uses the **original destination** (before REDIRECT) so the hash matches what other tools (e.g. Zeek, Suricata) would compute for the same flow.
- **TLS**: `tls.client.server_name` (SNI), `tls.client.supported_protocols` (ALPN list) and `tls.client.hash.ja4` (JA4 fingerprint), all read from the ClientHello.
- **Raw ClientHello**: `tls.client.hello_hex` holds the handshake record exactly as it arrived, header included. Every fingerprint above is derived from these bytes and each one discards something: JA4 sorts the extension list, JA3 keeps its order, and neither keeps GREASE placement or the extension bodies. Keeping the record is what lets you check a fingerprint, recompute it after a bug, or compute a scheme that did not exist when the traffic was captured. A hello is a few hundred bytes; capture stops at 16 KiB per connection. Set `capture_client_hello = false` to turn it off.
- **SSH**: `ssh.client.hash.hassh` (Hassh), when the payload starts with `SSH-2.0-` and contains a KEXINIT.
- **HTTP** - From the request head: `http.request.hash.akin` (Akin). The token carries a presence map over a fixed list of headers and short codes for the rest, so the distance between two tokens is the number of headers the two clients differ by, and header order never changes it. Scanners that rotate their User-Agent keep one fingerprint, because neither the User-Agent value nor the request path is part of it.

All of these are additive; existing behaviour (local log, Loom, payload hex, HTTP parsing) is unchanged.

**References (for verification and attribution):**  
Community ID: [Corelight Community ID spec](https://github.com/corelight/community-id-spec).  
JA4: [FoxIO JA4](https://github.com/FoxIO-LLC/ja4).  
Hassh: [Salesforce HASSH](https://github.com/salesforce/hassh).  
Akin: [honeylabshq/akin](https://github.com/honeylabshq/akin).  
TLS fingerprinting uses [github.com/psanford/tlsfingerprint](https://github.com/psanford/tlsfingerprint) (MIT).

## UDP capture (DNS and QUIC)

Off by default. With `udp_enabled = true` Spip also listens for UDP on the same port (or `udp_port`) and records every datagram it is handed. It never sends a reply. DNS, NTP, SNMP, memcached and SSDP are all amplification vectors, and a sensor that answers spoofed requests becomes a reflector aimed at whoever the spoofer chose.

Each datagram is classified in this order:

- QUIC. A client's Initial packets are decrypted with the public Initial keys (RFC 9001 section 5.2; versions 1, 2 and draft-29). CRYPTO frames are reassembled by offset, which handles Chromium's scrambled frame order and ClientHellos split across datagrams by post-quantum key shares. Retransmissions are folded in, so one connection attempt is one record. The ClientHello yields the same `tls.client.*` fields as TCP, with a JA4 that starts with `q`. `quic.client.transport_parameters.hash` fingerprints the QUIC implementation from its transport parameters. Values that change per connection are left out, including the GREASE version Chromium inserts at random. In testing it separated curl (ngtcp2), Chromium and quic-go while staying stable across connections from each. Unknown versions padded to 1200 bytes are recorded as version probes. An attempt whose ClientHello never completes is recorded after three seconds with the bytes that arrived.
- DNS. Queries and unsolicited responses (backscatter from someone spoofing the sensor's address) are decoded into the ECS `dns.*` fields, with EDNS details under `dns.edns`. `event.summary` reads like `DNS query TXT/CH version.bind`.
- Anything else is kept as raw UDP with its payload, as TCP probes are.

Every UDP record carries `network.transport: udp` and a Community ID over protocol 17. UDP source addresses are not authenticated. A UDP record says what was sent, but not reliably who sent it, so it must not feed address reputation or blocklists the way TCP records do.

### Host setup

A plain nat `REDIRECT`, the way the TCP side works, is not enough for UDP on its own. The kernel rewrites the destination before the socket sees it, and UDP has no `SO_ORIGINAL_DST`, so every event would carry Spip's own port. This was measured in a lab namespace: a datagram to port 53 arrived reporting port 7999.

Spip supports two ways around that, and the capture script picks one automatically:

- **TPROXY** (mangle table), used wherever the kernel has the target. The datagram reaches Spip's transparent socket unchanged and the socket reads the real destination. Needs `CAP_NET_ADMIN`; Spip runs as root on the sensors.
- **REDIRECT with a conntrack lookup** (nat table), for kernels without a working TPROXY. Spip asks conntrack over netlink for the flow whose reply direction matches the datagram it received, and takes the original destination from that entry. Needs read access to ctnetlink. The lookup runs only after the drop list and rate limits have admitted a datagram, and pauses for 30 seconds after three failed lookups in a row, so a flood or a stuck netlink socket cannot stall the reader. In the lab both modes recorded identical destination ports for IPv4 and IPv6.

The script picks REDIRECT inside an OpenVZ or Virtuozzo container and wherever the kernel refuses a TPROXY rule. Accepting the rule does not prove TPROXY delivers: an OpenVZ container accepts it and then passes nothing through. On other platforms, look at the first datagrams after `up`, and pin `MODE=redirect` if the TPROXY rule counts packets that never reach Spip.

`scripts/udp-capture.sh` installs the rule. Run `print` first to see exactly what it will do:

```bash
PORT=8080 ./scripts/udp-capture.sh print
PORT=8080 ./scripts/udp-capture.sh up      # idempotent; MODE=tproxy or MODE=redirect to force one
./scripts/udp-capture.sh down
```

The script leaves alone everything the host needs. It skips loopback, so local resolvers such as systemd-resolved on 127.0.0.53 keep working. It skips replies to the host's own traffic (conntrack ESTABLISHED under TPROXY; under REDIRECT the nat table only sees new flows), broadcast and multicast, and every port with a non-loopback UDP listener at install time, read from `/proc/net/udp*`, such as WireGuard, Tailscale and DHCP. Pass `EXEMPT="..."` for more. It adds no fwmark or routing table, because the honeypot addresses are already local. The usual TPROXY recipe with a mark and a local routing table fails on hosts with `src_valid_mark=1`, which WireGuard tooling sets: reverse-path filtering then drops every packet as martian.

Every input is treated as hostile. A global limit (`udp_rate_limit_per_second`, default 50, `udp_rate_limit_burst`, default 500) sits behind a per-source limit (`udp_source_rate_limit_per_second`, default 5, `udp_source_rate_limit_burst`, default 20) keyed by IPv4 address or IPv6 /64, so one sender cannot spend the whole budget. At most 2 KB of each datagram is stored, while `source.bytes` keeps its real size. Pending QUIC attempts are capped at 1024 of 8 KB each. Attacker-supplied text (DNS names, ALPN values, close reasons) is escaped to printable ASCII. Drops, limits, kernel receive-buffer overflows (`SO_RXQ_OVFL`) and folded QUIC retransmissions are reported hourly and at shutdown.

## Loom (optional log shipping)

Part of [log output](#log-output): when `[loom]` has `enabled = true`, the same ECS records are also batched and POSTed to your Loom ingest URL. Required when enabled: `url`, `sensor_id`, `token`. Optional: `batch_size` (default 50), `flush_interval` (e.g. `"10s"`), `insecure_skip_verify` (for self-signed Loom certs). The exporter runs asynchronously and does not block the capture loop; failed POSTs are logged to stderr and the batch is dropped (fail-open).

## Project Structure
```
.
├── cmd/                 # Main application entry point
├── internal/            # Config, logging, network, TLS, fingerprinting, exporters (e.g. Loom),
│                        # udp (capture), quic (Initial decryption), dnsinfo (DNS decoding)
├── pkg/                 # Linux socket helpers (SO_ORIGINAL_DST, transparent UDP)
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

## License

Business Source License 1.1, see [LICENSE](LICENSE).

In plain terms: you may read, modify and redistribute the code, and run it in production for your own organization, for example to watch your own networks or for research and teaching. You may not use it, or data it collects or processes, to make money from third parties. Selling it, running it for customers, or selling feeds, reports or threat intelligence built on its data needs a commercial license, available from info@honeylabs.net. Four years after each version's first public release, that version becomes available under the Apache License 2.0.

This summary is for convenience. The LICENSE file is what applies.
