package udp

import (
	"net/netip"
	"sync"
	"time"
)

// sourceLimiter caps datagrams per source so one sender, or one IPv6 /64,
// cannot spend the global budget. The table is bounded; when it is full and
// no entry has gone idle, new sources are refused rather than admitted.
type sourceLimiter struct {
	mu      sync.Mutex
	rate    float64
	burst   float64
	max     int
	idle    time.Duration
	buckets map[netip.Addr]*bucket
}

type bucket struct {
	tokens float64
	last   time.Time
}

func newSourceLimiter(rate float64, burst, max int) *sourceLimiter {
	return &sourceLimiter{
		rate: rate, burst: float64(burst), max: max, idle: time.Minute,
		buckets: make(map[netip.Addr]*bucket, max/4),
	}
}

func sourceKey(a netip.Addr) netip.Addr {
	a = a.Unmap()
	if a.Is6() {
		p, _ := a.Prefix(64)
		return p.Addr()
	}
	return a
}

func (l *sourceLimiter) allow(a netip.Addr, now time.Time) bool {
	k := sourceKey(a)
	l.mu.Lock()
	defer l.mu.Unlock()
	b, ok := l.buckets[k]
	if !ok {
		if len(l.buckets) >= l.max && !l.evict(now) {
			return false
		}
		b = &bucket{tokens: l.burst, last: now}
		l.buckets[k] = b
	}
	b.tokens = min(l.burst, b.tokens+now.Sub(b.last).Seconds()*l.rate)
	b.last = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

func (l *sourceLimiter) evict(now time.Time) bool {
	freed := false
	for k, b := range l.buckets {
		if now.Sub(b.last) > l.idle {
			delete(l.buckets, k)
			freed = true
		}
	}
	return freed
}
