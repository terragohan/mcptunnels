package oauth

import (
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// ipLimiter is a small per-IP token-bucket rate limiter with idle-entry
// eviction. Used to keep the open DCR endpoint from being flooded.
type ipLimiter struct {
	mu      sync.Mutex
	limit   rate.Limit
	burst   int
	window  time.Duration
	entries map[string]*ipEntry
}

type ipEntry struct {
	limiter  *rate.Limiter
	lastSeen time.Time
}

// newIPLimiter allows count events per window per IP (burst = count).
func newIPLimiter(count int, window time.Duration) *ipLimiter {
	return &ipLimiter{
		limit:   rate.Every(window / time.Duration(count)),
		burst:   count,
		window:  window,
		entries: make(map[string]*ipEntry),
	}
}

func (l *ipLimiter) allow(ip string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	e, ok := l.entries[ip]
	if !ok {
		e = &ipEntry{limiter: rate.NewLimiter(l.limit, l.burst)}
		l.entries[ip] = e
	}
	e.lastSeen = time.Now()
	// Occasional sweep of idle entries so the map doesn't grow forever.
	if len(l.entries) > 1024 {
		cutoff := time.Now().Add(-l.window)
		for k, v := range l.entries {
			if v.lastSeen.Before(cutoff) {
				delete(l.entries, k)
			}
		}
	}
	return e.limiter.Allow()
}
