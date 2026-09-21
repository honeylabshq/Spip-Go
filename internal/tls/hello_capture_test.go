package tls

import (
	"encoding/hex"
	"net"
	"os"
	"testing"
	"time"

	tlsfingerprint "github.com/psanford/tlsfingerprint"
)

// A real ClientHello from curl/OpenSSL, captured off the wire. Embedded rather
// than read from disk so this runs everywhere, including CI.
const sampleClientHelloHex = "1603010128010001240303014138be13e89a0b711b20ffe943830c78b7b98bbbcfe8f6580d741f08a5b3c8200c5abb86113dbc9d4a6bd2e1f1e2e58084b684511648ed9748f929c1ace31a180062130313021301cca9cca8ccaac030c02cc028c024c014c00a009f006b0039ff8500c400880081009d003d003500c00084c02fc02bc027c023c013c009009e0067003300be0045009c003c002f00ba0041c011c00700050004c012c0080016000a00ff01000079002b0009080304030303020301003300260024001d0020dd5aa9eeec23d6cb0ae01f3be07432e8e744588c1b057a1e8487ec68526bb348000b00020100000a000a0008001d001700180019000d00180016080606010603080505010503080404010403020102030010000e000c02683208687474702f312e31"

const (
	sampleJA4 = "t13i4906h2_0d8feac7bc37_7395dae3b2f3"
	sampleJA3 = "4f2655722e37c542ebeaf1eed48cbbbb"
)

type feedConn struct {
	data []byte
	pos  int
}

func (c *feedConn) Read(p []byte) (int, error) {
	if c.pos >= len(c.data) {
		return 0, os.ErrDeadlineExceeded
	}
	n := copy(p, c.data[c.pos:])
	c.pos += n
	return n, nil
}
func (c *feedConn) Write(p []byte) (int, error)      { return len(p), nil }
func (c *feedConn) Close() error                     { return nil }
func (c *feedConn) LocalAddr() net.Addr              { return &net.TCPAddr{} }
func (c *feedConn) RemoteAddr() net.Addr             { return &net.TCPAddr{} }
func (c *feedConn) SetDeadline(time.Time) error      { return nil }
func (c *feedConn) SetReadDeadline(time.Time) error  { return nil }
func (c *feedConn) SetWriteDeadline(time.Time) error { return nil }

// The whole point of keeping the hello is being able to recompute from it. If
// the stored record cannot reproduce the fingerprints the live path produced,
// storing it buys nothing.
func TestRecordedHelloReproducesFingerprints(t *testing.T) {
	raw, err := hex.DecodeString(sampleClientHelloHex)
	if err != nil {
		t.Fatal(err)
	}

	// The fingerprinter reads through a bufio.Reader and can pull more than
	// the record, so the recorder is trimmed. Simulate that over-read.
	over := append(append([]byte{}, raw...), []byte("GET / HTTP/1.1\r\n\r\n")...)
	got := clientHelloRecord(over)
	if got == nil {
		t.Fatal("record not recognised")
	}
	if hex.EncodeToString(got) != sampleClientHelloHex {
		t.Fatalf("recorded %d bytes, want %d, and they must be byte-identical",
			len(got), len(raw))
	}

	fp, err := tlsfingerprint.ParseClientHello(got)
	if err != nil {
		t.Fatalf("stored record does not parse: %v", err)
	}
	if fp.JA4String() != sampleJA4 {
		t.Errorf("JA4 from stored record = %s, want %s", fp.JA4String(), sampleJA4)
	}
	if fp.JA3Hash() != sampleJA3 {
		t.Errorf("JA3 from stored record = %s, want %s", fp.JA3Hash(), sampleJA3)
	}

	live, _, err := tlsfingerprint.FingerprintConn(&feedConn{data: raw})
	if err != nil {
		t.Fatal(err)
	}
	if live.JA4String() != fp.JA4String() || live.JA3Hash() != fp.JA3Hash() {
		t.Error("the live path and the stored record disagree")
	}
}

// A partial or non-handshake record must yield nothing. Storing a truncated
// hello as if it were whole would produce fingerprints that are quietly wrong.
func TestPartialHelloIsNotStored(t *testing.T) {
	for name, in := range map[string][]byte{
		"truncated":     {0x16, 0x03, 0x01, 0x01, 0x00, 0x01, 0x02},
		"not handshake": {0x17, 0x03, 0x01, 0x00, 0x01, 0x00},
		"too short":     {0x16, 0x03},
		"empty":         nil,
	} {
		if clientHelloRecord(in) != nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// The recorder must not let one peer make us hold an unbounded buffer.
func TestRecorderStopsAtTheCap(t *testing.T) {
	rec := &helloRecorder{Conn: &feedConn{data: make([]byte, MaxClientHelloBytes*3)}}
	buf := make([]byte, 4096)
	for i := 0; i < 100; i++ {
		if _, err := rec.Read(buf); err != nil {
			break
		}
	}
	if len(rec.buf) > MaxClientHelloBytes {
		t.Errorf("recorder held %d bytes, cap is %d", len(rec.buf), MaxClientHelloBytes)
	}
}
