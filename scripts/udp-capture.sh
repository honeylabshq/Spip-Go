#!/bin/sh
# Route inbound UDP to spip, for sensors that enable udp_enabled.
#
#   PORT=8080 ./udp-capture.sh print   # show the rules, change nothing
#   PORT=8080 ./udp-capture.sh up      # install (idempotent)
#   ./udp-capture.sh down              # remove everything this script added
#
# Two ways to deliver, picked automatically (override with MODE=tproxy or
# MODE=redirect):
#
#   tproxy    mangle-table TPROXY. The datagram reaches spip's transparent
#             socket untouched and the socket reads the real destination.
#   redirect  nat-table REDIRECT, for hosts whose kernel has no TPROXY target
#             (container platforms that do not expose the module). The kernel
#             rewrites the destination to spip, and spip reads the original
#             one back from conntrack over netlink.
#
# The nat REDIRECT the TCP side uses would also lose the port for UDP on its
# own, because UDP has no SO_ORIGINAL_DST; the conntrack lookup is what makes
# redirect mode correct.
#
# The honeypot addresses are local to the sensor, so no fwmark or policy
# routing table is needed, and none is added. That matters on hosts with
# net.ipv4.conf.all.src_valid_mark=1 (set by WireGuard tooling): there the
# usual "fwmark -> local table" recipe makes reverse-path filtering drop every
# packet as martian.
#
# What is NOT captured, so the host keeps working:
#   - loopback: local resolvers (127.0.0.53) and other local UDP services
#   - replies to the host's own traffic: DNS answers, NTP, anything the host
#     asked for (conntrack ESTABLISHED/RELATED in tproxy mode; in redirect
#     mode the nat table only ever sees the first packet of a new flow)
#   - broadcast and multicast (only destination type LOCAL is taken)
#   - ports with a real UDP listener on the host (WireGuard, DHCP), found in
#     /proc/net/udp* at install time, plus anything in EXEMPT
#
# spip never replies to UDP, so conntrack keeps every captured flow in state
# NEW; only flows the host itself answered become ESTABLISHED.
set -eu

PORT="${PORT:-8080}"
EXEMPT="${EXEMPT:-}"
MODE="${MODE:-auto}"
CHAIN=SPIP_UDP

listeners() {
	# Unconnected UDP sockets reachable from outside, minus spip's own. Read
	# from /proc rather than ss, which crashes inside some containers.
	# Loopback-only listeners are skipped: the "-i lo" rule already keeps
	# them working, and counting them would exempt port 53 on every host
	# running systemd-resolved (127.0.0.53:53), which silently turns DNS
	# capture off.
	for f in /proc/net/udp /proc/net/udp6; do
		[ -r "$f" ] || continue
		awk 'NR > 1 {
			split($2, l, ":"); split($3, r, ":")
			if (r[1] !~ /^0+$/) next
			ip = l[1]
			if (length(ip) == 8 && substr(ip, 7, 2) == "7F") next
			if (ip == "00000000000000000000000001000000") next
			if (length(ip) == 32 && substr(ip, 17, 8) == "FFFF0000" && substr(ip, 31, 2) == "7F") next
			print l[2]
		}' "$f"
	done | while read -r hex; do printf '%d\n' "0x$hex"; done |
		grep -vx "$PORT" | sort -un
}

# TPROXY is available when the kernel accepts a rule using it. Probed in a
# scratch chain that is removed again, so nothing live changes.
has_tproxy() {
	iptables -t mangle -N SPIP_UDP_PROBE 2>/dev/null || iptables -t mangle -F SPIP_UDP_PROBE
	ok=1
	iptables -t mangle -A SPIP_UDP_PROBE -p udp -j TPROXY --on-port "$PORT" 2>/dev/null && ok=0
	iptables -t mangle -F SPIP_UDP_PROBE 2>/dev/null
	iptables -t mangle -X SPIP_UDP_PROBE 2>/dev/null
	return $ok
}

mode() {
	case "$MODE" in
	tproxy | redirect) echo "$MODE" ;;
	auto) if has_tproxy; then echo tproxy; else echo redirect; fi ;;
	*)
		echo "MODE must be auto, tproxy or redirect" >&2
		exit 2
		;;
	esac
}

table() { [ "$1" = tproxy ] && echo mangle || echo nat; }

rules() {
	m=$1
	ports="$(listeners) $EXEMPT"
	echo "-A $CHAIN -i lo -j RETURN"
	[ "$m" = tproxy ] && echo "-A $CHAIN -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN"
	echo "-A $CHAIN -m addrtype ! --dst-type LOCAL -j RETURN"
	for p in $ports; do
		echo "-A $CHAIN -p udp --dport $p -j RETURN"
	done
	if [ "$m" = tproxy ]; then
		echo "-A $CHAIN -p udp -j TPROXY --on-port $PORT"
	else
		echo "-A $CHAIN -p udp -j REDIRECT --to-ports $PORT"
	fi
}

apply() {
	tool=$1 m=$2 t=$(table "$2")
	$tool -t "$t" -N "$CHAIN" 2>/dev/null || $tool -t "$t" -F "$CHAIN"
	rules "$m" | while read -r line; do
		# shellcheck disable=SC2086
		$tool -t "$t" $line
	done
	$tool -t "$t" -C PREROUTING -p udp -j "$CHAIN" 2>/dev/null ||
		$tool -t "$t" -A PREROUTING -p udp -j "$CHAIN"
}

remove() {
	tool=$1
	for t in mangle nat; do
		while $tool -t "$t" -D PREROUTING -p udp -j "$CHAIN" 2>/dev/null; do :; done
		$tool -t "$t" -F "$CHAIN" 2>/dev/null || true
		$tool -t "$t" -X "$CHAIN" 2>/dev/null || true
	done
}

case "${1:-print}" in
print)
	m=$(mode)
	echo "# mode: $m (table $(table "$m"))"
	echo "# exempt listener ports: $(listeners | tr '\n' ' ')${EXEMPT:+ extra: $EXEMPT}"
	echo "-N $CHAIN"
	rules "$m"
	echo "-A PREROUTING -p udp -j $CHAIN"
	;;
up)
	m=$(mode)
	# Switching modes must not leave the other table's chain behind.
	remove iptables
	apply iptables "$m"
	if command -v ip6tables >/dev/null; then
		remove ip6tables
		apply ip6tables "$m" 2>/dev/null || echo "IPv6 UDP capture unavailable on this host" >&2
	fi
	echo "spip UDP capture installed ($m): unanswered inbound UDP -> :$PORT"
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
