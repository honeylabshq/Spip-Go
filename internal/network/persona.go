package network

import "bytes"

// persona is a minimal, low-interaction protocol responder selected by the
// original destination port (preserved across the iptables REDIRECT via
// SO_ORIGINAL_DST). The goal is narrow: say *just enough* to make a scanner
// reveal its next stage — credentials, an attack command sequence — without
// emulating a real service. No shell, no state machine beyond a tiny counter.
// Anything not matched falls back to the default behaviour (HTTP 200 + the
// client's own IP, or the IP echoed for non-HTTP), unchanged.
type personaKind int

const (
	personaDefault personaKind = iota
	personaRedis
	personaTelnet
)

// personaForPort maps an original destination port to a responder. Ports not
// listed use personaDefault, so the agent's existing behaviour is untouched
// everywhere except these few high-signal services.
func personaForPort(port int) personaKind {
	switch port {
	case 6379, 6380: // Redis (+ common TLS/alt port)
		return personaRedis
	case 23, 2323: // Telnet (+ common IoT alt port)
		return personaTelnet
	}
	return personaDefault
}

// looksLikeRedis catches a Redis client hitting a non-standard port. RESP
// arrays begin with '*' followed by a digit and CRLF; inline commands start
// with a bare PING/AUTH. Deliberately conservative so arbitrary probes (and
// the unit tests' "Hello, TCP!") never match.
func looksLikeRedis(payload []byte) bool {
	if len(payload) >= 4 && payload[0] == '*' && payload[1] >= '1' && payload[1] <= '9' {
		return true
	}
	up := bytes.ToUpper(bytes.TrimSpace(payload))
	return bytes.HasPrefix(up, []byte("PING")) || bytes.HasPrefix(up, []byte("AUTH "))
}

// redisReply returns a minimal RESP reply so the attacker keeps sending its
// command sequence (CONFIG SET, SLAVEOF, MODULE LOAD, cron payloads — the
// whole attack, which we then capture). Redis is auth-less by default, so
// accepting AUTH and answering PING is enough to keep most loaders going.
func redisReply(payload []byte) []byte {
	up := bytes.ToUpper(payload)
	switch {
	case bytes.Contains(up, []byte("PING")):
		return []byte("+PONG\r\n")
	case bytes.Contains(up, []byte("QUIT")):
		return []byte("+OK\r\n")
	default:
		// AUTH, CONFIG, SET, SLAVEOF, MODULE, INFO, … all get a generic +OK.
		return []byte("+OK\r\n")
	}
}

// Telnet greeting: a token IAC negotiation (WILL ECHO, WILL SUPPRESS-GO-AHEAD)
// followed by a login prompt. Mirai-style IoT bots wait for this prompt before
// sending credentials, so we send it on connect (before the first read).
var telnetGreeting = append([]byte{
	255, 251, 1, // IAC WILL ECHO
	255, 251, 3, // IAC WILL SUPPRESS-GO-AHEAD
}, []byte("\r\nlogin: ")...)

// hasPrintable reports whether payload carries human-entered text once telnet
// IAC control sequences are skipped. Used so pure option negotiation (which a
// client sends in response to our IAC) doesn't get mistaken for a username and
// advance the login flow prematurely.
func hasPrintable(payload []byte) bool {
	for i := 0; i < len(payload); i++ {
		b := payload[i]
		if b == 255 { // IAC — skip the following command (+ option) bytes
			i += 2
			continue
		}
		if b > ' ' && b < 0x7f { // a visible, non-space ASCII char
			return true
		}
	}
	return false
}

// telnetReply drives a tiny login flow: prompt for a password after the
// username arrives, then close after the password. stage is advanced in place;
// done=true tells the caller to stop reading and drop the connection (a real
// failed login). Stage 0 = awaiting username, 1 = awaiting password.
func telnetReply(stage *int) (reply []byte, done bool) {
	switch *stage {
	case 0:
		*stage = 1
		return []byte("\r\nPassword: "), false
	default:
		*stage = 2
		return []byte("\r\nLogin incorrect\r\n"), true
	}
}
