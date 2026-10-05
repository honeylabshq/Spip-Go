package udp

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

// testdata/quic_captures.json holds client Initial datagrams captured in an
// isolated network namespace on 2026-10-05 from curl 8.21 (ngtcp2), Chromium
// 151 and quic-go v0.63 (QUIC v1 and v2), with the JA4 tshark 4.6 computed
// from the same packets. Replaying them checks decryption, reassembly of
// Chromium's scrambled CRYPTO frames and the fingerprint against an
// independent implementation, on real bytes rather than on packets this
// codebase sealed itself.
type capture struct {
	Name      string   `json:"name"`
	Port      uint16   `json:"port"`
	DCID      string   `json:"dcid"`
	TsharkJA4 string   `json:"tshark_ja4"`
	SNI       string   `json:"sni"`
	Datagrams []string `json:"datagrams"`
}

func TestRealClientCaptures(t *testing.T) {
	raw, err := os.ReadFile("testdata/quic_captures.json")
	if err != nil {
		t.Fatal(err)
	}
	var caps []capture
	if err := json.Unmarshal(raw, &caps); err != nil {
		t.Fatal(err)
	}
	if len(caps) < 6 {
		t.Fatalf("only %d captures", len(caps))
	}
	hashByImpl := map[string]string{}
	for i, c := range caps {
		t.Run(c.Name, func(t *testing.T) {
			r := newRig(t, Options{})
			for _, h := range c.Datagrams {
				d, err := hex.DecodeString(h)
				if err != nil {
					t.Fatal(err)
				}
				r.send(d, 50000+i, c.Port)
			}
			recs := r.records()
			if len(recs) != 1 {
				t.Fatalf("%d records, want 1", len(recs))
			}
			m := recs[0]
			if got := get(m, "tls.client.hash.ja4"); got != c.TsharkJA4 {
				t.Errorf("ja4 %v, tshark says %s", got, c.TsharkJA4)
			}
			if c.SNI != "" && get(m, "tls.client.server_name") != c.SNI {
				t.Errorf("sni %v, want %s", get(m, "tls.client.server_name"), c.SNI)
			}
			if get(m, "quic.dcid") != c.DCID || get(m, "quic.hello_complete") != true {
				t.Errorf("quic %v", m["quic"])
			}
			impl := c.Name[:4]
			h, _ := get(m, "quic.client.transport_parameters.hash").(string)
			if prev, ok := hashByImpl[impl]; ok && prev != h {
				t.Errorf("%s transport hash changed between connections: %s then %s", impl, prev, h)
			}
			hashByImpl[impl] = h
		})
	}
	// Three implementations, three different transport parameter hashes.
	seen := map[string]string{}
	for impl, h := range hashByImpl {
		if other, dup := seen[h]; dup {
			t.Errorf("%s and %s share transport hash %s", impl, other, h)
		}
		seen[h] = impl
	}
	if len(hashByImpl) != 3 {
		t.Errorf("implementations %v", hashByImpl)
	}
}
