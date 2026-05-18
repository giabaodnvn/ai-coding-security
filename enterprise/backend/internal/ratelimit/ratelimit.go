package ratelimit

import (
	"sync"
	"time"
)

const (
	maxRequests = 60
	windowSize  = time.Minute
)

type Limiter struct {
	mu      sync.Mutex
	buckets map[string]*bucket
}

type bucket struct {
	count   int
	resetAt time.Time
}

func New() *Limiter {
	return &Limiter{buckets: make(map[string]*bucket)}
}

// Allow returns true if the key is within its rate limit quota.
func (l *Limiter) Allow(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := time.Now()
	b, ok := l.buckets[key]
	if !ok || now.After(b.resetAt) {
		l.buckets[key] = &bucket{count: 1, resetAt: now.Add(windowSize)}
		return true
	}
	if b.count >= maxRequests {
		return false
	}
	b.count++
	return true
}
