#!/bin/sh
# Route inbound UDP to spip with TPROXY, for sensors that enable udp_enabled.
#
#   PORT=8080 ./udp-capture.sh print   # show the rules, change nothing
#   PORT=8080 ./udp-capture.sh up      # install (idempotent)
#   ./udp-capture.sh down              # remove everything this script added
#
# Why TPROXY and not the nat REDIRECT the TCP side uses: REDIRECT rewrites the
# destination before spip sees the datagram and UDP has no SO_ORIGINAL_DST, so
# every event would carry spip's own port. TPROXY delivers the datagram
# untouched to spip's transparent socket, which reads the real destination.
#
# The honeypot addresses are local to the sensor, so no fwmark or policy
# routing table is needed, and none is added. That matters on hosts with
# net.ipv4.conf.all.src_valid_mark=1 (set by WireGuard tooling): there the
# usual "fwmark -> local table" recipe makes reverse-path filtering drop every
# packet as martian.
#
# What is NOT captured, so the host keeps working:
#   - loopback: local resolvers (127.0.0.53) and other local UDP services
#   - replies to the host's own traffic (conntrack ESTABLISHED/RELATED): DNS
#     answers, NTP, anything the host asked for
#   - broadcast and multicast (only destination type LOCAL is taken)
#   - ports with a real UDP listener on the host (WireGuard, Tailscale, DHCP),
#     found with ss at install time, plus anything in EXEMPT
#
# spip never replies to UDP, so conntrack keeps every captured flow in state
# NEW; only flows the host itself answered become ESTABLISHED.
set -eu

PORT="${PORT:-8080}"
EXEMPT="${EXEMPT:-}"
CHAIN=SPIP_UDP

listeners() {
	# Ports with a UDP socket reachable from outside, minus spip's own.
	# Loopback-only listeners are skipped: the "-i lo" rule already keeps
	# them working, and counting them would exempt port 53 on every host
	# running systemd-resolved (127.0.0.53:53), which silently turns DNS
	# capture off. Found in the lab on 2026-10-05.
	ss -Huln 2>/dev/null | awk '{print $4}' |
		grep -vE '^(127\.|\[::1\]|::1)|%lo:' |
		sed -E 's/.*:([0-9]+)$/\1/' |
		grep -E '^[0-9]+$' | grep -vx "$PORT" | sort -un
}

rules() {
	ports="$(listeners) $EXEMPT"
	echo "-A $CHAIN -i lo -j RETURN"
	echo "-A $CHAIN -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN"
	echo "-A $CHAIN -m addrtype ! --dst-type LOCAL -j RETURN"
	for p in $ports; do
		echo "-A $CHAIN -p udp --dport $p -j RETURN"
	done
	echo "-A $CHAIN -p udp -j TPROXY --on-port $PORT"
}

apply() {
	tool=$1
	$tool -t mangle -N "$CHAIN" 2>/dev/null || $tool -t mangle -F "$CHAIN"
	rules | while read -r line; do
		# shellcheck disable=SC2086
		$tool -t mangle $line
	done
	$tool -t mangle -C PREROUTING -p udp -j "$CHAIN" 2>/dev/null ||
		$tool -t mangle -A PREROUTING -p udp -j "$CHAIN"
}

remove() {
	tool=$1
	while $tool -t mangle -D PREROUTING -p udp -j "$CHAIN" 2>/dev/null; do :; done
	$tool -t mangle -F "$CHAIN" 2>/dev/null || true
	$tool -t mangle -X "$CHAIN" 2>/dev/null || true
}

case "${1:-print}" in
print)
	echo "# exempt listener ports: $(listeners | tr '\n' ' ')${EXEMPT:+ extra: $EXEMPT}"
	echo "-N $CHAIN"
	rules
	echo "-A PREROUTING -p udp -j $CHAIN"
	;;
up)
	apply iptables
	command -v ip6tables >/dev/null && apply ip6tables
	echo "spip UDP capture installed: unanswered inbound UDP -> :$PORT"
	;;
down)
	remove iptables
	command -v ip6tables >/dev/null && remove ip6tables
	echo "spip UDP capture removed"
	;;
*)
	echo "usage: $0 print|up|down" >&2
	exit 2
	;;
esac
