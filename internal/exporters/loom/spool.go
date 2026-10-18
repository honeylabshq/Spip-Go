package loom

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Spool is the on-disk queue of batches waiting for Loom: one file per batch,
// its content the JSON array exactly as it goes on the wire, its name ordering
// it after everything written before it. Every batch goes through the spool,
// so a batch Loom could not take waits there with the ones after it and the
// sender always posts the oldest file first. A file is deleted only after a
// 2xx, so a batch Loom took is never sent again from here.
//
// Three limits remove batches unsent, always the oldest first and always
// counted through onDrop: the size cap, the age cap, and the free space the
// filesystem must keep. Nothing else is ever lost here. Only the index (name,
// size, count per file) is held in memory, so a long outage costs disk, not
// RAM.
//
// The design is the Feint exporter's spool, adapted to Spip.
type Spool struct {
	dir     string
	max     int64         // size cap in bytes
	maxAge  time.Duration // age cap
	minFree uint64        // bytes the filesystem must keep free after a write

	// now and freeSpace are replaced in tests.
	now       func() time.Time
	freeSpace func(dir string) (uint64, bool)
	// onDrop reports documents removed unsent and why ("size", "age",
	// "disk", "corrupt"). Called with mu held, so it must not call back in.
	onDrop func(reason string, docs int)

	mu    sync.Mutex
	files []entry // in posting order
	total int64
	seq   uint64
}

// entry is one spooled batch.
type entry struct {
	name string
	size int64
	n    int       // documents in the batch
	born time.Time // when the batch was first written, from its name
}

// errLowDisk refuses a batch the filesystem has no room for even after the
// whole spool was given up for it.
var errLowDisk = errors.New("not enough free disk space for the spool")

// OpenSpool creates or reopens the spool at dir. Batches left by an earlier
// run are picked up in order; a write that a crash left half done (*.tmp) is
// removed, since its batch never reached a name the sender reads.
func OpenSpool(dir string, maxBytes int64, maxAge time.Duration, minFree uint64) (*Spool, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	s := &Spool{dir: dir, max: maxBytes, maxAge: maxAge, minFree: minFree,
		now: time.Now, freeSpace: diskFree, onDrop: func(string, int) {}}
	list, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	for _, d := range list {
		name := d.Name()
		if d.IsDir() {
			continue
		}
		if strings.HasSuffix(name, ".tmp") {
			_ = os.Remove(filepath.Join(dir, name))
			continue
		}
		born, n, ok := parseName(name)
		if !ok {
			continue
		}
		info, err := d.Info()
		if err != nil {
			continue
		}
		s.files = append(s.files, entry{name: name, size: info.Size(), n: n, born: born})
		s.total += info.Size()
	}
	sort.Slice(s.files, func(i, j int) bool { return s.files[i].name < s.files[j].name })
	// A probe write proves the directory takes files before anything is
	// trusted to it.
	probe := filepath.Join(dir, ".probe.tmp")
	if err := os.WriteFile(probe, nil, 0o600); err != nil {
		return nil, err
	}
	_ = os.Remove(probe)
	return s, nil
}

// parseName reads the write time and document count out of a spool file name
// (<unix nanos>-<seq>-<n>.json, the seq extended by a/b on a split); other
// files are not the spool's.
func parseName(name string) (time.Time, int, bool) {
	stem, ok := strings.CutSuffix(name, ".json")
	if !ok {
		return time.Time{}, 0, false
	}
	parts := strings.Split(stem, "-")
	if len(parts) != 3 {
		return time.Time{}, 0, false
	}
	nanos, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil || nanos < 0 {
		return time.Time{}, 0, false
	}
	n, err := strconv.Atoi(parts[2])
	if err != nil || n < 0 {
		return time.Time{}, 0, false
	}
	return time.Unix(0, nanos), n, true
}

// Put appends a batch of n documents. On errLowDisk or a write error the
// batch is not in the spool and the caller keeps it.
func (s *Spool) Put(body []byte, n int) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.expireLocked()
	if err := s.makeRoomLocked(int64(len(body))); err != nil {
		return err
	}
	s.seq++
	name := fmt.Sprintf("%020d-%06d-%d.json", s.now().UnixNano(), s.seq, n)
	if err := s.write(name, body); err != nil {
		return err
	}
	s.files = append(s.files, entry{name: name, size: int64(len(body)), n: n, born: s.now()})
	s.total += int64(len(body))
	s.enforceLocked()
	return nil
}

// write lands body at name through a temporary file that is synced before the
// rename, so neither a crash nor a power cut leaves a partial batch under a
// name the sender would read.
func (s *Spool) write(name string, body []byte) error {
	tmp := filepath.Join(s.dir, name+".tmp")
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	_, err = f.Write(body)
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Rename(tmp, filepath.Join(s.dir, name))
	}
	if err != nil {
		_ = os.Remove(tmp)
	}
	return err
}

// makeRoomLocked keeps minFree bytes free on the filesystem after a write of
// size bytes, giving up the oldest batches if it has to. When the whole spool
// is not enough the write is refused.
func (s *Spool) makeRoomLocked(size int64) error {
	free, ok := s.freeSpace(s.dir)
	if !ok {
		return nil
	}
	need := uint64(size) + s.minFree
	for free < need && len(s.files) > 0 {
		old := s.files[0]
		s.dropFrontLocked("disk")
		free += uint64(old.size)
	}
	if free < need {
		return errLowDisk
	}
	return nil
}

// enforceLocked removes the oldest files while the spool is over its size
// cap, never the newest.
func (s *Spool) enforceLocked() {
	for s.total > s.max && len(s.files) > 1 {
		s.dropFrontLocked("size")
	}
}

// expireLocked removes batches older than the age cap from the front.
// Batches are in write order, so the first young one ends the scan.
func (s *Spool) expireLocked() {
	if s.maxAge <= 0 {
		return
	}
	cutoff := s.now().Add(-s.maxAge)
	for len(s.files) > 0 && s.files[0].born.Before(cutoff) {
		s.dropFrontLocked("age")
	}
}

func (s *Spool) dropFrontLocked(reason string) {
	old := s.files[0]
	_ = os.Remove(filepath.Join(s.dir, old.name))
	s.files = s.files[1:]
	s.total -= old.size
	s.onDrop(reason, old.n)
}

// Oldest returns the next batch to post: its name, body and document count,
// or ok false when the spool is empty. Expired batches are removed first. A
// file that cannot be read, or is not a JSON array, is removed and the next
// one returned, so one damaged file never stalls everything behind it.
func (s *Spool) Oldest() (name string, body []byte, n int, ok bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.expireLocked()
	for len(s.files) > 0 {
		e := s.files[0]
		b, err := os.ReadFile(filepath.Join(s.dir, e.name))
		if err != nil || !json.Valid(b) {
			s.dropFrontLocked("corrupt")
			continue
		}
		return e.name, b, e.n, true
	}
	return "", nil, 0, false
}

// Remove deletes a batch Loom took (or refused for good). It reports an
// error only when the file is still on disk, which would resend it after a
// restart.
func (s *Spool) Remove(name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, e := range s.files {
		if e.name == name {
			s.files = append(s.files[:i], s.files[i+1:]...)
			s.total -= e.size
			if err := os.Remove(filepath.Join(s.dir, e.name)); err != nil && !os.IsNotExist(err) {
				return err
			}
			return nil
		}
	}
	return nil
}

// Split replaces a batch Loom found too large with its two halves, in its
// place in the order (the halves' names extend the original's, so they sort
// where it was and keep its age). The documents' bytes are copied unchanged.
// A batch of one cannot be split and ok is false; a batch the caps removed
// meanwhile is reported as split, since there is nothing left to post.
func (s *Spool) Split(name string, body []byte) (ok bool, err error) {
	var docs []json.RawMessage
	if err := json.Unmarshal(body, &docs); err != nil {
		return false, err
	}
	if len(docs) < 2 {
		return false, nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	at := -1
	for i, e := range s.files {
		if e.name == name {
			at = i
			break
		}
	}
	if at < 0 {
		return true, nil
	}
	orig := s.files[at]
	stem := strings.TrimSuffix(name, ".json")
	stem = stem[:strings.LastIndexByte(stem, '-')]
	mid := len(docs) / 2
	var added []entry
	for i, half := range [][]json.RawMessage{docs[:mid], docs[mid:]} {
		b := joinDocs(half)
		n := fmt.Sprintf("%s%c-%d.json", stem, 'a'+rune(i), len(half))
		if err := s.write(n, b); err != nil {
			for _, a := range added {
				_ = os.Remove(filepath.Join(s.dir, a.name))
			}
			return false, err
		}
		added = append(added, entry{name: n, size: int64(len(b)), n: len(half), born: orig.born})
	}
	_ = os.Remove(filepath.Join(s.dir, orig.name))
	s.total -= orig.size
	rest := append([]entry{}, s.files[at+1:]...)
	s.files = append(append(s.files[:at], added...), rest...)
	for _, e := range added {
		s.total += e.size
	}
	return true, nil
}

// joinDocs builds a JSON array from documents without re-encoding them.
func joinDocs(docs []json.RawMessage) []byte {
	size := 2
	for _, d := range docs {
		size += len(d) + 1
	}
	b := make([]byte, 0, size)
	b = append(b, '[')
	for i, d := range docs {
		if i > 0 {
			b = append(b, ',')
		}
		b = append(b, d...)
	}
	return append(b, ']')
}

// Stats is what the spool holds: batches, bytes and documents.
func (s *Spool) Stats() (files int, bytes int64, docs int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, e := range s.files {
		docs += e.n
	}
	return len(s.files), s.total, docs
}
