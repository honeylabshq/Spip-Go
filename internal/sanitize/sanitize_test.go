package sanitize

import "testing"

func TestPrintable(t *testing.T) {
	cases := []struct {
		in   []byte
		max  int
		want string
	}{
		{[]byte("example.com"), 64, "example.com"},
		{[]byte("a\x00b\nc\xff"), 64, `a\x00b\x0ac\xff`},
		{[]byte(`back\slash`), 64, `back\\slash`},
		{[]byte("<script>"), 64, "<script>"},
		{[]byte("abcdef"), 3, "abc"},
	}
	for _, c := range cases {
		if got := Printable(c.in, c.max); got != c.want {
			t.Errorf("Printable(%q) = %q, want %q", c.in, got, c.want)
		}
	}
	if IsPrintable([]byte("ok"), 1) || IsPrintable(nil, 8) || IsPrintable([]byte("a\x01"), 8) || !IsPrintable([]byte("ok"), 8) {
		t.Error("IsPrintable")
	}
}
