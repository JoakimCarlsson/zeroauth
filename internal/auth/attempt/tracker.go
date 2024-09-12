package attempt

import (
	"sync"
	"time"
)

type AuthAttempt struct {
	Timestamp  time.Time
	Successful bool
}

type Tracker struct {
	attempts      map[string][]AuthAttempt
	blockedUntil  map[string]time.Time
	mu            sync.RWMutex
	maxAttempts   int
	blockDuration time.Duration
}

func NewTracker(maxAttempts int, blockDuration time.Duration) *Tracker {
	t := &Tracker{
		attempts:      make(map[string][]AuthAttempt),
		blockedUntil:  make(map[string]time.Time),
		maxAttempts:   maxAttempts,
		blockDuration: blockDuration,
	}
	go t.cleanupBlockedUsers()
	return t
}

func (t *Tracker) AddAttempt(identifier string, successful bool) {
	t.mu.Lock()
	defer t.mu.Unlock()

	attempt := AuthAttempt{
		Timestamp:  time.Now(),
		Successful: successful,
	}

	t.attempts[identifier] = append(t.attempts[identifier], attempt)

	if len(t.attempts[identifier]) > t.maxAttempts {
		t.attempts[identifier] = t.attempts[identifier][len(t.attempts[identifier])-t.maxAttempts:]
	}

	if !successful {
		failedAttempts := 0
		for i := len(t.attempts[identifier]) - 1; i >= 0; i-- {
			if time.Since(t.attempts[identifier][i].Timestamp) > t.blockDuration {
				break
			}
			if !t.attempts[identifier][i].Successful {
				failedAttempts++
			}
		}

		if failedAttempts >= t.maxAttempts {
			t.blockedUntil[identifier] = time.Now().Add(t.blockDuration)
		}
	}
}

func (t *Tracker) ShouldBlock(identifier string) bool {
	t.mu.RLock()
	defer t.mu.RUnlock()

	if blockTime, exists := t.blockedUntil[identifier]; exists {
		if time.Now().Before(blockTime) {
			return true
		}
	}

	return false
}

func (t *Tracker) ResetAttempts(identifier string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.attempts, identifier)
	delete(t.blockedUntil, identifier)
}

func (t *Tracker) Cleanup() {
	t.mu.Lock()
	defer t.mu.Unlock()

	now := time.Now()
	for identifier, attempts := range t.attempts {
		var validAttempts []AuthAttempt
		for _, attempt := range attempts {
			if now.Sub(attempt.Timestamp) <= t.blockDuration {
				validAttempts = append(validAttempts, attempt)
			}
		}
		if len(validAttempts) > 0 {
			t.attempts[identifier] = validAttempts
		} else {
			delete(t.attempts, identifier)
		}
	}

	for identifier, blockTime := range t.blockedUntil {
		if now.After(blockTime) {
			delete(t.blockedUntil, identifier)
		}
	}
}

func (t *Tracker) cleanupBlockedUsers() {
	ticker := time.NewTicker(t.blockDuration)
	defer ticker.Stop()

	for range ticker.C {
		t.Cleanup()
	}
}
