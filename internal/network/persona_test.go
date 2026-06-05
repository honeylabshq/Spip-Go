package network

import (
	"bytes"
	"testing"
)

func TestPersonaForPort(t *testing.T) {
	cases := map[int]personaKind{
		6379:  personaRedis,
		6380:  personaRedis,
		23:    personaTelnet,
		2323:  personaTelnet,
		80:    personaDefault,
		443:   personaDefault,
		8080:  personaDefault,
		0:     personaDefault,
		54321: personaDefault, // ephemeral (what the unit tests connect on)
	}
	for port, want := range cases {
		if got := personaForPort(port); got != want {
			t.Errorf("personaForPort(%d) = %v, want %v", port, got, want)
		}
	}
}

func TestLooksLikeRedis(t *testing.T) {
	redis := [][]byte{
		[]byte("*1\r\n$4\r\nPING\r\n"),
		[]byte("*3\r\n$3\r\nSET\r\n$1\r\na\r\n$1\r\nb\r\n"),
		[]byte("PING\r\n"),
		[]byte("ping"),
		[]byte("AUTH secret\r\n"),
	}
	for _, p := range redis {
		if !looksLikeRedis(p) {
			t.Errorf("looksLikeRedis(%q) = false, want true", p)
		}
	}
	notRedis := [][]byte{
		[]byte("Hello, TCP!"),             // the generic handler test payload
		[]byte("GET / HTTP/1.1\r\n"),      // HTTP
		[]byte("\x16\x03\x01\x00"),        // TLS ClientHello
		[]byte(""),                        // empty
		[]byte("*"),                       // too short / no count
		[]byte("AUTHORIZATION: Bearer x"), // 'AUTH' as a prefix but not the command
	}
	for _, p := range notRedis {
		if looksLikeRedis(p) {
			t.Errorf("looksLikeRedis(%q) = true, want false", p)
		}
	}
}

func TestRedisReply(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"*1\r\n$4\r\nPING\r\n", "+PONG\r\n"},
		{"PING\r\n", "+PONG\r\n"},
		{"AUTH foobar\r\n", "+OK\r\n"},
		{"*4\r\n$6\r\nCONFIG\r\n$3\r\nSET\r\n$3\r\ndir\r\n$10\r\n/var/spool\r\n", "+OK\r\n"},
		{"SLAVEOF 1.2.3.4 6379\r\n", "+OK\r\n"},
		{"QUIT\r\n", "+OK\r\n"},
	}
	for _, c := range cases {
		if got := redisReply([]byte(c.in)); string(got) != c.want {
			t.Errorf("redisReply(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestTelnetReply(t *testing.T) {
	stage := 0
	// First reply (after the username): prompt for the password, keep reading.
	reply, done := telnetReply(&stage)
	if done {
		t.Error("telnet stage 0 should not be done")
	}
	if !bytes.Contains(reply, []byte("Password:")) {
		t.Errorf("telnet stage 0 reply should prompt for password, got %q", reply)
	}
	if stage != 1 {
		t.Errorf("telnet stage should advance to 1, got %d", stage)
	}
	// Second reply (after the password): reject and close.
	reply, done = telnetReply(&stage)
	if !done {
		t.Error("telnet stage 1 should be done (drop after password)")
	}
	if !bytes.Contains(reply, []byte("incorrect")) {
		t.Errorf("telnet stage 1 reply should reject, got %q", reply)
	}
}

func TestHasPrintable(t *testing.T) {
	yes := [][]byte{
		[]byte("admin"),
		[]byte("root\r\n"),
		append([]byte{255, 251, 1}, []byte("user")...), // IAC WILL ECHO + "user"
	}
	for _, p := range yes {
		if !hasPrintable(p) {
			t.Errorf("hasPrintable(%q) = false, want true", p)
		}
	}
	no := [][]byte{
		{255, 251, 1, 255, 251, 3}, // pure IAC negotiation
		{255, 253, 24},             // IAC DO TERMINAL-TYPE
		[]byte("\r\n"),             // bare CRLF
		[]byte("   "),              // only spaces
		{},                         // empty
	}
	for _, p := range no {
		if hasPrintable(p) {
			t.Errorf("hasPrintable(%q) = true, want false", p)
		}
	}
}

func TestTelnetGreetingPromptsLogin(t *testing.T) {
	if !bytes.Contains(telnetGreeting, []byte("login:")) {
		t.Errorf("telnet greeting must contain a login prompt, got %q", telnetGreeting)
	}
	// Must start with an IAC byte so it reads as telnet, not plain text.
	if telnetGreeting[0] != 255 {
		t.Errorf("telnet greeting should begin with IAC (255), got %d", telnetGreeting[0])
	}
}
