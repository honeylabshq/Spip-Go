package quic

import (
	"testing"
	"time"
)

func FuzzParseDatagram(f *testing.F) {
	hello := realHello(f, "fuzz.example", testTP)
	f.Add(sealInitial(f, Version1, []byte{1, 2, 3, 4, 5, 6, 7, 8}, []byte{9}, 0, cryptoFrame(0, hello)))
	f.Add(sealInitial(f, Version2, []byte{1, 2, 3, 4}, nil, 1, cryptoFrame(40, hello[40:])))
	f.Add([]byte{0xc0, 0x1a, 0x2a, 0x3a, 0x4a, 8, 1, 2, 3, 4, 5, 6, 7, 8, 0})
	f.Fuzz(func(t *testing.T, b []byte) {
		pkts, _ := ParseDatagram(b)
		a := NewAssembler()
		for i, p := range pkts {
			if at := a.Add("k", time.Unix(0, 0), p, b, nil, i == 0); at != nil {
				_, _ = ParseHello(at.Hello)
			}
		}
		a.Expire(time.Unix(100, 0))
	})
}

func FuzzParseHello(f *testing.F) {
	f.Add(realHello(f, "fuzz.example", testTP))
	f.Add([]byte{0x01, 0x00, 0x00, 0x00})
	f.Fuzz(func(t *testing.T, b []byte) {
		h, err := ParseHello(b)
		if err == nil && h.ServerName != "" && len(h.ServerName) > maxServerName {
			t.Fatalf("server name of %d bytes", len(h.ServerName))
		}
	})
}

func FuzzDescribeParams(f *testing.F) {
	f.Add(testTP)
	f.Fuzz(func(t *testing.T, b []byte) {
		if params, err := parseTransportParams(b); err == nil {
			_ = describeParams(params)
		}
	})
}
