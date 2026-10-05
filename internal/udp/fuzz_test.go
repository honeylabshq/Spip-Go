package udp

import (
	"encoding/hex"
	"io"
	"net"
	"testing"

	"spip/internal/logging"
	"spip/internal/quic"
	"spip/internal/quic/quictest"
	"spip/pkg/socket"
)

func FuzzHandleDatagram(f *testing.F) {
	hello := quictest.Hello(f, "fuzz.example", tp)
	f.Add(quictest.Seal(f, quic.Version1, []byte{1, 2, 3, 4, 5, 6, 7, 8}, nil, 0, quictest.Crypto(0, hello)))
	q, _ := hex.DecodeString("abcd01000001000000000000076578616d706c6503636f6d0000ff0001")
	f.Add(q)
	f.Add([]byte("\xff\xff\xff\xffgetstatus\n"))
	s := NewServer(logging.NewLogger(io.Discard), Options{RatePerSecond: 1e9, Burst: 1 << 30, SourceRate: 1e9, SourceBurst: 1 << 30})
	src := &net.UDPAddr{IP: net.ParseIP("198.51.100.7"), Port: 4000}
	dst := &socket.OriginalDst{IP: net.IPv4(192, 0, 2, 1), Port: 443}
	f.Fuzz(func(t *testing.T, b []byte) {
		s.HandleDatagram(b, src, dst)
		if s.panics.Load() != 0 {
			t.Fatal("handler panicked")
		}
	})
}
