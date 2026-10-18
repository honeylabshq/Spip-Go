# Spip - Network Honeypot Sensor

Spip is a low-interaction network honeypot sensor for Linux, written in Go. It accepts TCP connections on any port the host redirects to it, plain or TLS, answers just enough to make a client send its next message, and writes each exchange as one JSON record with ECS field names, ready for a SIEM or data lake. Optional UDP capture records datagrams and never answers them.

HoneyLabs runs Spip to collect the data published on [honeylabs.net](https://honeylabs.net).

## Quick Start

Prerequisites:
- Linux. The agent uses Linux socket options and does not build for other systems.
- Go 1.27 or later
- `iptables` and root access to install the redirect rules

1) Build the agent
```bash
git clone https://github.com/honeylabshq/Spip-Go.git
cd Spip-Go
go build -o spip-agent ./cmd/spip-agent
```
To set the version reported in `observer.version` and `agent.version` (default `dev`), add `-ldflags "-X main.version=v1.2.3"`.

2) (Optional) Use the interactive setup helper
```bash
sudo ./scripts/initial_setup.sh
```
See [Initial setup helper](#initial-setup-helper) below.

3) Create or edit `config.toml`
Minimal `config.toml`:
```toml
name = "spip-agent"
ip = "0.0.0.0"
port = 8080
```

Optional configuration keys:
- `cert_path` / `key_path`: enable TLS if both are set. Relative paths resolve against the directory of the config file.
- `log_file`: append records to this file instead of stdout. See [Log output](#log-output) below.
- `[loom]`: also ship records over HTTP. See [Loom](#loom-optional-log-shipping) below.
- `read_timeout_seconds` / `write_timeout_seconds`: idle read timeout and write timeout per connection.
- `rate_limit_per_second` / `rate_limit_burst`: rate limit on new TCP connections, shared by all sources. A connection over the limit is closed unread.
- `community_id_seed`: optional 16-bit seed for Community ID v1 flow hashing (omit or `0` for the default).
- `capture_client_hello`: set `false` to leave out `tls.client.hello_hex`. See [Fingerprinting](#fingerprinting).
- `ignore_sources`: addresses or networks whose connections and datagrams are closed or discarded before anything is read, so they are never logged, fingerprinted or shipped. Bare addresses and CIDR, IPv4 or IPv6:
  `ignore_sources = ["192.0.2.10", "198.51.100.0/24", "2001:db8::/32"]`. A honeypot on a rented host gets polled by that host's own monitoring, and counting those scrapes distorts port rankings and scanner counts. An entry that does not parse stops the agent from starting, because a typo here would silently record traffic you believe is dropped. Drops are counted per source and reported in the log every hour and at shutdown.
- `udp_enabled` and the `udp_*` keys: see [UDP capture](#udp-capture-dns-and-quic).

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
The first command flushes the whole nat table. Leave it out on a host that has NAT rules of its own. The same two rules with `ip6tables` cover IPv6. Spip reads each connection's original destination from the kernel's connection tracking and records it as `destination.ip` and `destination.port`.

5) Run the agent
```bash
./spip-agent -config config.toml
```
`-config` is the only flag and defaults to `config.toml` in the working directory. SIGINT or SIGTERM stops the listener, waits up to 15 seconds for open connections and writes any pending Loom batch to the spool, giving it 5 seconds to send; the rest is sent at the next start.

## Responses

Spip picks a responder by the original destination port. Each one says only enough to make the client send its next message: credentials, a command or a mail envelope.

| Ports | Response |
|-------|----------|
| 23, 2323 | Telnet option negotiation and a `login:` prompt, then `Password:`, then `Login incorrect` and close |
| 21, 990 | FTP greeting, a password request after the first line, then `530 Login incorrect.` and close |
| 25, 465, 587 | SMTP greeting, `250` replies to the first three lines, `354` to the fourth, then close. Nothing is relayed and no outbound connection is made. |
| 110, 995 | POP3 greeting, `+OK` after the first line, `-ERR invalid login` after the second, then close |
| 143, 993 | IMAP greeting, then `* BAD Login failed` and close |
| 6379, 6380, or any payload that looks like a Redis command | `+PONG` to PING, `+OK` to everything else |
| any other port | `HTTP/1.1 200 OK` with the client's IP address as the body for an HTTP request, the bare IP address for anything else |

A client that sends `SSH-2.0` without a key exchange message gets the banner `SSH-2.0-spip`, and Spip waits up to 2 seconds for the key exchange so it can compute the client fingerprint.

The telnet, FTP, SMTP, POP3 and IMAP greetings are sent on connect. With TLS enabled, Spip first reads one byte to tell TLS from plain text, so those greetings only go out after the client has sent something.

## Log output

Spip writes ECS logs to a single local destination and can also send the same records to a Loom server:

| Destination | Config | Behaviour |
|-------------|--------|-----------|
| Local | `log_file` | Omitted or empty: stdout. Set to a path: records are appended to that file. Always on. |
| Loom | `[loom]` with `enabled = true` | Optional. The same records are batched and POSTed to your Loom ingest URL in addition to the local output. |

The local output also carries the agent's own log lines, such as hourly drop counts and warnings, as `{"timestamp": <unix seconds>, "level": "INFO", "message": "...", "target": "...", "record_type": "log"}`. Only connection records go to Loom. Startup messages go to stderr.

## Log format

Spip writes each record as a single line of JSON with ECS field names, using only what it can derive from the connection itself (no ASN or geo enrichment). A connection that sends several messages produces one record per message, all with the same `event.id`. Fields include:
- `@timestamp`: RFC 3339 time of the record, in whole seconds
- `event.id`: per-connection session identifier; `event.sequence`: the record's position in the session, starting at 1
- `event.duration`: nanoseconds since the connection opened
- `event.module`, `event.dataset` (`spip.tcp` or `spip.udp`), `event.kind`, `event.category`, `event.type`: let a SIEM select Spip's records
- `observer.vendor`, `observer.product`, `observer.type`, `observer.version`, `agent.type`, `agent.version`
- `observer.hostname`, `observer.id` and `host.name`: the agent `name` from config
- `source.ip`, `source.port`, `destination.ip`, `destination.port`
- `source.bytes`, `destination.bytes`, `network.bytes`: bytes received and sent in the session so far
- `network.transport` (`tcp` or `udp`) and `network.protocol` (`tls`, `dns`, `netbios` or `quic`) where known
- `http.request.method`, `http.request.headers`, `http.request.body.content`, `http.request.body.bytes`, `url.path`, `url.domain`, `url.port`: when the payload is an HTTP request
- `user_agent.original`: when available
- `event.summary`: the payload as text, for payloads that are not HTTP requests
- `event.original_payload_hex`: the raw payload in hex, always kept
- [Fingerprinting](#fingerprinting) adds `network.community_id`, `tls.client.*`, `ssh.client.hash.hassh` and `http.request.hash.akin` when they apply.

Example record, pretty-printed:
```json
{
  "@timestamp": "2026-10-12T09:14:03Z",
  "agent": {"type": "spip", "version": "dev"},
  "destination": {"bytes": 78, "ip": "203.0.113.10", "port": 80},
  "event": {
    "category": ["network", "intrusion_detection"],
    "dataset": "spip.tcp",
    "duration": 100000000,
    "id": "3f0c9a52-6d1e-4b8a-9c27-5e41b7d08a6f",
    "ingested_by": "spip",
    "kind": "event",
    "module": "spip",
    "original_payload_hex": "474554202f2e656e7620485454502f312e310d0a486f73743a203230332e302e3131332e31300d0a557365722d4167656e743a204d6f7a696c6c612f352e300d0a4163636570743a202a2f2a0d0a436f6e6e656374696f6e3a20636c6f73650d0a0d0a",
    "sequence": 1,
    "type": ["connection", "info"]
  },
  "host": {"name": "example-sensor"},
  "http": {
    "request": {
      "hash": {"akin": "b11cun040_00040015_4c87b06e"},
      "headers": {
        "accept": "*/*",
        "connection": "close",
        "host": "203.0.113.10",
        "user-agent": "Mozilla/5.0"
      },
      "method": "GET"
    }
  },
  "network": {"bytes": 177, "community_id": "1:HL0iYZHtkKWecl0HBQsLeL+lIc8=", "transport": "tcp"},
  "observer": {
    "hostname": "example-sensor",
    "id": "example-sensor",
    "product": "Spip",
    "type": "honeypot",
    "vendor": "HoneyLabs",
    "version": "dev"
  },
  "source": {"bytes": 99, "ip": "198.51.100.23", "port": 51234},
  "url": {"domain": "203.0.113.10", "path": "/.env"},
  "user_agent": {"original": "Mozilla/5.0"}
}
```

Downstream systems can enrich these records (geo, ASN and so on) if desired.

## Fingerprinting

Spip adds passive fingerprinting fields to each record without changing what it captures:

- `network.community_id`: Community ID v1 flow hash of the 5-tuple (source and destination IP and port, protocol). When traffic is redirected through iptables, Spip hashes the original destination from before the REDIRECT, so the value matches what other network monitoring computes for the same flow.
- `tls.client.server_name` (SNI), `tls.client.supported_protocols` (the ALPN list the client offered), `tls.client.hash.ja4` and `tls.client.ja3`, all read from the ClientHello. TLS also adds `tls.client.version`, `tls.client.cipher` and, when the client presents a certificate, `tls.client.client_certificate.*`. These fields need `cert_path` and `key_path`. Without them a TLS handshake is recorded as raw payload. A TLS connection whose handshake fails is closed without a record.
- `tls.client.hello_hex`: the ClientHello record exactly as it arrived, header included. Every fingerprint above is derived from these bytes and each one discards part of them, such as extension order, GREASE placement or extension bodies. Keeping the record lets you check a fingerprint, recompute it after a bug, or compute a scheme that did not exist when the traffic was captured. A hello is a few hundred bytes and capture stops at 16 KiB per connection. Set `capture_client_hello = false` to turn it off.
- `ssh.client.hash.hassh`: when the payload starts with `SSH-2.0-` and contains a KEXINIT.
- `http.request.hash.akin`: an [Akin](https://github.com/honeylabshq/akin) token computed from the request head. The token carries a presence map over a fixed list of headers and short codes for the rest, so the distance between two tokens is the number of headers the two clients differ by, and header order never changes it. Scanners that rotate their User-Agent keep one fingerprint, because neither the User-Agent value nor the request path is part of it.

## UDP capture (DNS and QUIC)

Off by default. With `udp_enabled = true` Spip also listens for UDP on the same port (or `udp_port`) and records every datagram it is handed. It never sends a reply. DNS, NTP, SNMP, memcached and SSDP are all amplification vectors, and a sensor that answers spoofed requests becomes a reflector aimed at whoever the spoofer chose.

Each datagram is classified in this order:

- QUIC. A client's Initial packets are decrypted with the public Initial keys (RFC 9001 section 5.2; versions 1, 2 and draft-29). CRYPTO frames are reassembled by offset, which handles clients that send frames out of order and ClientHellos split across datagrams by post-quantum key shares. Retransmissions are folded in, so one connection attempt is one record. The ClientHello yields the same `tls.client.*` fields as TCP, and `tls.client.hash.ja4` starts with `q`. `quic.client.transport_parameters.hash` fingerprints the QUIC implementation from its transport parameters. Values that change per connection are left out, including randomly inserted GREASE versions, so the hash stays stable across connections from one client while telling different QUIC stacks apart. Unknown versions in datagrams padded to 1200 bytes are recorded as version probes. An attempt whose ClientHello never completes is recorded after three seconds with the bytes that arrived.
- DNS. A datagram counts as DNS only when it frames as exactly one message with at least one valid question, allowing up to 4 bytes of zero, CR or LF padding (counted in `dns.trailing_bytes`). Queries and unsolicited responses (backscatter from someone spoofing the sensor's address) are decoded into the ECS `dns.*` fields, with EDNS details under `dns.edns`. `event.summary` reads like `DNS query TXT/CH version.bind`.
- NetBIOS name service. It shares the DNS wire format but names NetBIOS names, so it is recorded as `network.protocol: netbios` with a summary such as `NetBIOS name query WORKGROUP<00>` and no `dns.*` fields.
- Anything else is kept as raw UDP with its payload, as TCP probes are.

Every UDP record carries `network.transport: udp` and a Community ID over protocol 17. UDP source addresses are not authenticated. A UDP record says what was sent, but not reliably who sent it, so it must not feed address reputation or blocklists the way TCP records do.

### Host setup

A plain nat `REDIRECT`, the way the TCP side works, is not enough for UDP on its own. The kernel rewrites the destination before the socket sees it, and UDP has no `SO_ORIGINAL_DST`, so every event would carry Spip's own port.

Spip supports two ways around that, and the capture script picks one automatically:

- TPROXY (mangle table), used wherever the kernel supports it. The datagram reaches Spip's transparent socket unchanged and the socket reads the real destination. The transparent socket needs `CAP_NET_ADMIN`.
- REDIRECT with a conntrack lookup (nat table), for kernels without a working TPROXY. Spip asks conntrack over netlink for the flow whose reply direction matches the datagram it received, and takes the original destination from that entry. The netlink lookup also needs `CAP_NET_ADMIN`. It runs only after the drop list and rate limits have admitted a datagram, and pauses for 30 seconds after three failed lookups in a row, so a flood or a stuck netlink socket cannot stall the reader.

The script picks REDIRECT inside containers that share the host kernel through `/proc/vz`, and wherever the kernel refuses a TPROXY rule. Accepting the rule does not prove TPROXY delivers: such a container accepts it and then passes nothing through. On other platforms, look at the first datagrams after `up`, and pin `MODE=redirect` if the TPROXY rule counts packets that never reach Spip.

`scripts/udp-capture.sh` installs the rules and needs root. Run `print` first to see exactly what it will do:

```bash
sudo PORT=8080 ./scripts/udp-capture.sh print
sudo PORT=8080 ./scripts/udp-capture.sh up      # idempotent; MODE=tproxy or MODE=redirect to force one
sudo ./scripts/udp-capture.sh down
```

The script leaves alone everything the host needs. It skips loopback, so local resolvers on 127.0.0.53 keep working. It skips replies to the host's own traffic (conntrack ESTABLISHED under TPROXY; under REDIRECT the nat table only sees new flows), broadcast and multicast, and every port with a non-loopback UDP listener at install time, read from `/proc/net/udp*`, such as a VPN endpoint or a DHCP client. Pass `EXEMPT="..."` for more. It adds no fwmark or routing table, because the honeypot addresses are already local. The usual TPROXY recipe with a mark and a local routing table fails on hosts with `src_valid_mark=1`, which some VPN tooling sets: reverse-path filtering then drops every packet as martian.

Every input is treated as hostile. A global limit (`udp_rate_limit_per_second`, default 50, `udp_rate_limit_burst`, default 500) sits behind a per-source limit (`udp_source_rate_limit_per_second`, default 5, `udp_source_rate_limit_burst`, default 20) keyed by IPv4 address or IPv6 /64, so one sender cannot spend the whole budget. At most 2 KB of each datagram is stored, while `source.bytes` keeps its real size. Pending QUIC attempts are capped at 1024 of 8 KB each. Attacker-supplied text (DNS names, ALPN values, close reasons) is escaped to printable ASCII. Drops, limits, kernel receive-buffer overflows (`SO_RXQ_OVFL`) and folded QUIC retransmissions are reported hourly and at shutdown.

## Loom (optional log shipping)

When `[loom]` has `enabled = true`, the same ECS records are also batched and POSTed as a JSON array to the Loom ingest URL, with `Authorization: Bearer <token>` and `X-Spip-ID: <sensor_id>` headers. Required when enabled: `url`, `sensor_id`, `token`. Optional: `batch_size` (default 50, at most 500), `flush_interval` (default `"10s"`), `insecure_skip_verify` (for self-signed Loom certificates), `spool_dir` (default `loom-spool` beside the config file; relative paths resolve against the config file's directory), `spool_max_size_mb` (default 512) and `spool_max_age` (default `"7d"`; a Go duration or a whole number of days).

```toml
[loom]
enabled = true
url = "https://loom.example.com/api/v1/ingest"
sensor_id = "spip-agent"
token = "..."
```

Every closed batch is first written to the spool directory, one file per batch holding the exact request body, through a synced temporary file and a rename so a crash never leaves a partial batch under a name that is replayed. A separate sender posts the oldest file and deletes it only after a 2xx, so a delivered batch is never sent again. After a failure it retries the same batch with a pause that doubles from 1 second to 1 minute, so an outage of hours is replayed when Loom answers again, and batches left by an earlier run are sent at the next start. Capture never waits on the network: the batcher only writes to disk, and only the spool's file index is kept in memory.

Responses: a 413 halves the batch in the spool until each part fits Loom's `max_body_size_bytes`, and a single record Loom still refuses is dropped and logged. A 429 is retried after its `Retry-After` (at most 10 seconds). 400 and 415 drop the batch, since a malformed body cannot succeed on retry. Everything else (5xx, transport errors, 401 and 403) is kept and retried, so fixing a token on either side delivers what waited.

The spool removes batches unsent only past its limits, always the oldest first: the size cap, the age cap, and 128 MB of free disk space it always leaves on the filesystem. When even an emptied spool cannot leave that much free, batches wait in a memory queue of at most 8 MB instead, which is also used when no spool directory can be created (a fallback under the system temp directory is tried first). Every removal is counted and logged on its first occurrence and then at most once an hour. If the queue to the exporter is ever full, records skip Loom but stay in the local output, and a warning is logged at most once a minute. Shipping messages are printed to stderr.

## Project Structure

- `cmd/spip-agent`: main application entry point
- `internal/`: config, logging (ECS records), network (TCP handler and responders), tls, fingerprint, udp, quic (Initial decryption), dnsinfo (DNS decoding), sanitize, exporters/loom
- `pkg/socket`: Linux socket helpers (original destination, transparent UDP)
- `pkg/conntrack`: conntrack lookups over netlink
- `test/e2e`: end-to-end tests
- `scripts/`: setup, UDP capture and test scripts

## Testing
Run unit tests with:
```bash
go test ./...
```
`make test` runs the same unit tests, and `make vet`, `make fmt` and `make check-fmt` cover the usual checks.

End-to-end tests require privileges to manipulate `iptables`. Run them via the script (from the repo root):
```bash
sudo -E ./scripts/run_e2e_tests.sh
```
The script builds the agent, flushes the nat table before and after the run, and accepts a test name to run a single test. Alternatively use the container helper, which needs Docker: `./scripts/run_e2e_in_container.sh`. E2E validates core behaviour (payload capture, source and original destination, TLS detection, Loom batching, fingerprinting).

## Notes on HTTP parsing and deployment

Spip performs best-effort HTTP request detection from the captured payload. A payload counts as an HTTP request when its first line is a request line (GET, POST, PUT, DELETE, HEAD, OPTIONS or PATCH, a path, HTTP/1.0 or HTTP/1.1) and it also has a blank line ending the head or a Host header. The agent then emits `http.*`, `url.*` and `user_agent.original` fields. Otherwise Spip stores the payload in `event.summary`. The raw payload hex in `event.original_payload_hex` is always kept.

Because Spip reflects the source IP in its responses and accepts arbitrary inbound TCP traffic, it is intended for use as a honeypot-style sensor or edge collector in controlled and monitored environments, not on arbitrary user endpoints.

## Initial setup helper
Run the interactive helper from the repo root as root:
```bash
sudo ./scripts/initial_setup.sh
```
The script prompts for: a short `name` (used in logs as `observer.hostname` and `host.name`), listen IP and port, the SSH port to exclude from the redirect, optional self-signed TLS certificate generation with `openssl` (paths are written relative to the config so they work from any directory), log file path, optional Loom configuration (URL, sensor_id, token, batch_size, flush_interval, TLS verification), optional timeouts and rate limits, and the optional iptables PREROUTING redirect. It writes `config.toml` in the repo root, replacing any existing one. Before changing iptables it saves the nat table to `/tmp/spip-iptables-nat-backup-<timestamp>.rules` and then flushes it. It does not configure UDP capture or `ignore_sources`.

## License

Spip is open source under the Apache License 2.0, see [LICENSE](LICENSE).
