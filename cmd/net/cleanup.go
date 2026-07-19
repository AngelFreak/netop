package main

import (
	"fmt"
	"os"
	"sync"
	"time"
)

// cleanupEntry is one registered cleanup action. done guards against running
// the action more than once (via run, or a deregister racing a run).
type cleanupEntry struct {
	name string
	fn   func()
	done bool
}

// cleanupRegistry holds cleanup actions to run on interrupt. Actions run in
// LIFO order — later registrations (deeper into a flow) undo first. All access
// is mutex-guarded so registration from command goroutines and execution from
// the signal goroutine are safe. It is deliberately minimal: the only state is
// the entry slice.
type cleanupRegistry struct {
	mu      sync.Mutex
	entries []*cleanupEntry
}

// defaultCleanups is the process-wide registry the signal handler drains and
// the App mutation sites register against.
var defaultCleanups = &cleanupRegistry{}

// register adds a cleanup action and returns a deregister func that removes it.
// Both register and the returned deregister are safe for concurrent use. The
// deregister is a no-op if the entry already ran.
func (r *cleanupRegistry) register(name string, fn func()) (deregister func()) {
	r.mu.Lock()
	defer r.mu.Unlock()
	e := &cleanupEntry{name: name, fn: fn}
	r.entries = append(r.entries, e)
	return func() {
		r.mu.Lock()
		defer r.mu.Unlock()
		for i, entry := range r.entries {
			if entry == e {
				r.entries = append(r.entries[:i], r.entries[i+1:]...)
				return
			}
		}
	}
}

// Len reports the number of registered (not-yet-run) entries. Used by tests.
func (r *cleanupRegistry) Len() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.entries)
}

// run executes all registered entries LIFO within an overall timeout budget,
// each entry at most once. Entries run in a goroutine so a hanging one is
// abandoned at the deadline instead of blocking process exit; abandoned
// entries are noted on stderr.
func (r *cleanupRegistry) run(timeout time.Duration) {
	r.mu.Lock()
	// Snapshot LIFO and mark consumed under the lock so a concurrent run or a
	// deregister can't touch the same entries.
	pending := make([]*cleanupEntry, 0, len(r.entries))
	for i := len(r.entries) - 1; i >= 0; i-- {
		e := r.entries[i]
		if e.done {
			continue
		}
		e.done = true
		pending = append(pending, e)
	}
	r.entries = nil
	r.mu.Unlock()

	deadline := time.Now().Add(timeout)
	for _, e := range pending {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			fmt.Fprintf(os.Stderr, "cleanup: timeout reached, skipping %q\n", e.name)
			continue
		}
		done := make(chan struct{})
		go func(fn func()) {
			defer close(done)
			fn()
		}(e.fn)
		select {
		case <-done:
		case <-time.After(remaining):
			fmt.Fprintf(os.Stderr, "cleanup: %q did not finish within budget, abandoning\n", e.name)
		}
	}
}
