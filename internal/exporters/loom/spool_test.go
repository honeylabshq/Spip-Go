package loom

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

type dropLog struct {
	mu sync.Mutex
	by map[string]int
}

func (d *dropLog) note(reason string, n int) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.by == nil {
		d.by = map[string]int{}
	}
	d.by[reason] += n
}

func (d *dropLog) get(reason string) int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.by[reason]
}

func openTestSpool(t *testing.T, dir string, max int64, age time.Duration) (*Spool, *dropLog) {
	t.Helper()
	s, err := OpenSpool(dir, max, age, 0)
	if err != nil {
		t.Fatal(err)
	}
	d := &dropLog{}
	s.onDrop = d.note
	s.freeSpace = func(string) (uint64, bool) { return 0, false }
	return s, d
}

func batch(ids ...string) []byte {
	return []byte(`[{"id":"` + strings.Join(ids, `"},{"id":"`) + `"}]`)
}

func TestSpoolReplaysOldestFirst(t *testing.T) {
	s, _ := openTestSpool(t, t.TempDir(), 1<<30, 0)
	for _, b := range [][]byte{batch("a"), batch("b", "c"), batch("d")} {
		if err := s.Put(b, bytes.Count(b, []byte(`"id"`))); err != nil {
			t.Fatal(err)
		}
	}
	var got []string
	for {
		name, body, _, ok := s.Oldest()
		if !ok {
			break
		}
		got = append(got, string(body))
		if err := s.Remove(name); err != nil {
			t.Fatal(err)
		}
	}
	want := []string{string(batch("a")), string(batch("b", "c")), string(batch("d"))}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("replay order %v, want %v", got, want)
	}
}

// The spool stores exactly the bytes it was given; a resend is the original
// request body.
func TestSpoolKeepsBytesAndOrderAcrossReopen(t *testing.T) {
	dir := t.TempDir()
	s, _ := openTestSpool(t, dir, 1<<30, 0)
	raw := []byte(`[{"msg":"<script>","n":1.5,"x":{"y":"é"}},{"id":"2"}]`)
	_ = s.Put(raw, 2)
	_ = s.Put(batch("3"), 1)

	s2, _ := openTestSpool(t, dir, 1<<30, 0)
	if files, _, docs := s2.Stats(); files != 2 || docs != 3 {
		t.Fatalf("reopened spool holds %d files, %d docs; want 2, 3", files, docs)
	}
	_, body, n, ok := s2.Oldest()
	if !ok || n != 2 || !bytes.Equal(body, raw) {
		t.Fatalf("first batch after reopen = %q (%d docs), want %q", body, n, raw)
	}
}

// A batch removed after a 2xx stays gone, also across a restart.
func TestSpoolRemovedBatchIsNeverReturnedAgain(t *testing.T) {
	dir := t.TempDir()
	s, _ := openTestSpool(t, dir, 1<<30, 0)
	_ = s.Put(batch("sent"), 1)
	_ = s.Put(batch("waiting"), 1)
	name, _, _, _ := s.Oldest()
	if err := s.Remove(name); err != nil {
		t.Fatal(err)
	}
	s2, _ := openTestSpool(t, dir, 1<<30, 0)
	_, body, _, _ := s2.Oldest()
	if !bytes.Equal(body, batch("waiting")) {
		t.Fatalf("after reopen got %q, the delivered batch came back", body)
	}
	if files, _, _ := s2.Stats(); files != 1 {
		t.Fatalf("spool holds %d files, want 1", files)
	}
}

func TestSpoolSizeCapDropsTheOldest(t *testing.T) {
	b := batch("xxxxxxxx")
	s, d := openTestSpool(t, t.TempDir(), int64(len(b))*3, 0)
	for i := 0; i < 5; i++ {
		_ = s.Put(batch(strings.Repeat(string(rune('a'+i)), 8)), 1)
	}
	if files, _, _ := s.Stats(); files != 3 {
		t.Fatalf("spool holds %d files, want 3", files)
	}
	if got := d.get("size"); got != 2 {
		t.Fatalf("size drops = %d, want 2", got)
	}
	_, body, _, _ := s.Oldest()
	if !bytes.Equal(body, batch("cccccccc")) {
		t.Fatalf("oldest left is %q, want the third batch", body)
	}
}

func TestSpoolAgeCapDropsOldBatches(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	s, d := openTestSpool(t, t.TempDir(), 1<<30, 7*24*time.Hour)
	s.now = func() time.Time { return now }
	_ = s.Put(batch("old1"), 1)
	_ = s.Put(batch("old2", "old3"), 2)
	now = now.Add(6 * 24 * time.Hour)
	_ = s.Put(batch("young"), 1)
	now = now.Add(2 * 24 * time.Hour) // the first two are now 8 days old

	_, body, _, ok := s.Oldest()
	if !ok || !bytes.Equal(body, batch("young")) {
		t.Fatalf("oldest = %q, want the young batch", body)
	}
	if got := d.get("age"); got != 3 {
		t.Fatalf("age drops = %d documents, want 3", got)
	}
}

// A crash in the middle of a write leaves a .tmp file; a power cut before the
// data reached disk can leave a short .json. Neither may corrupt the replay.
func TestSpoolCrashLeftoversDoNotCorruptReplay(t *testing.T) {
	dir := t.TempDir()
	s, _ := openTestSpool(t, dir, 1<<30, 0)
	_ = s.Put(batch("good1"), 1)
	_ = s.Put(batch("good2"), 1)
	files, _ := os.ReadDir(dir)
	// A half-written temp file of a later batch, and the first batch cut short.
	tmp := filepath.Join(dir, "99999999999999999999-000009-1.json.tmp")
	if err := os.WriteFile(tmp, []byte(`[{"id":"hal`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, files[0].Name()), []byte(`[{"id":"go`), 0o600); err != nil {
		t.Fatal(err)
	}

	s2, d := openTestSpool(t, dir, 1<<30, 0)
	if _, err := os.Stat(tmp); !os.IsNotExist(err) {
		t.Fatalf("the half-written temp file survived reopen: %v", err)
	}
	name, body, _, ok := s2.Oldest()
	if !ok || !bytes.Equal(body, batch("good2")) {
		t.Fatalf("oldest = %q, want the intact batch", body)
	}
	if d.get("corrupt") != 1 {
		t.Fatalf("corrupt drops = %d, want 1", d.get("corrupt"))
	}
	_ = s2.Remove(name)
	if _, _, _, ok := s2.Oldest(); ok {
		t.Fatal("spool should be empty")
	}
}

// A failed write never leaves a file the sender would read.
func TestSpoolWriteGoesThroughTempAndRename(t *testing.T) {
	dir := t.TempDir()
	s, _ := openTestSpool(t, dir, 1<<30, 0)
	_ = s.Put(batch("a"), 1)
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".tmp") {
			t.Fatalf("temp file left behind: %s", e.Name())
		}
	}
	if len(entries) != 1 {
		t.Fatalf("spool dir holds %d files, want 1", len(entries))
	}
}

func TestSpoolLowDiskGivesUpOldestThenRefuses(t *testing.T) {
	s, d := openTestSpool(t, t.TempDir(), 1<<30, 0)
	s.minFree = 100
	free := uint64(1 << 20)
	s.freeSpace = func(string) (uint64, bool) { return free, true }
	_ = s.Put(batch("a"), 1)
	_ = s.Put(batch("b"), 1)

	// Room for one more only once the oldest batch is given up.
	free = 100 + uint64(len(batch("c"))) - uint64(len(batch("a")))
	if err := s.Put(batch("c"), 1); err != nil {
		t.Fatal(err)
	}
	if d.get("disk") != 1 {
		t.Fatalf("disk drops = %d, want 1", d.get("disk"))
	}
	_, body, _, _ := s.Oldest()
	if !bytes.Equal(body, batch("b")) {
		t.Fatalf("oldest = %q, want b", body)
	}

	free = 0
	if err := s.Put(batch("d"), 1); !errors.Is(err, errLowDisk) {
		t.Fatalf("Put on a full disk = %v, want errLowDisk", err)
	}
	if files, _, _ := s.Stats(); files != 0 {
		t.Fatalf("spool holds %d files after giving everything up, want 0", files)
	}
}

func TestSpoolSplitKeepsBytesPlaceAndAge(t *testing.T) {
	dir := t.TempDir()
	s, _ := openTestSpool(t, dir, 1<<30, 0)
	big := []byte(`[{"id":"1","p":"<&>"},{"id":"2"},{"id":"3"}]`)
	_ = s.Put(big, 3)
	_ = s.Put(batch("later"), 1)
	name, body, _, _ := s.Oldest()
	ok, err := s.Split(name, body)
	if !ok || err != nil {
		t.Fatalf("split = %v, %v", ok, err)
	}
	var got []string
	for {
		name, body, _, ok := s.Oldest()
		if !ok {
			break
		}
		got = append(got, string(body))
		_ = s.Remove(name)
	}
	want := []string{`[{"id":"1","p":"<&>"}]`, `[{"id":"2"},{"id":"3"}]`, string(batch("later"))}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("after split %v, want %v", got, want)
	}

	if ok, _ := s.Split("x", batch("one")); ok {
		t.Fatal("a batch of one cannot be split")
	}
}

func TestParseName(t *testing.T) {
	for name, want := range map[string]int{
		"00000000000000000001-000001-5.json":   5,
		"00000000000000000001-000001ab-2.json": 2,
	} {
		if _, n, ok := parseName(name); !ok || n != want {
			t.Errorf("parseName(%q) = %d, %v", name, n, ok)
		}
	}
	for _, name := range []string{"x.json", "1-2.json", "1-2-3.json.tmp", "a-b-c.json", ".probe.tmp"} {
		if _, _, ok := parseName(name); ok {
			t.Errorf("parseName(%q) accepted a foreign file", name)
		}
	}
}
