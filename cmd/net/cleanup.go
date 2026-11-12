package main

import (
	"context"
	"fmt"
	"os"
	"sync"
	"time"
)

// cleanupEntry is one registered cleanup action.
type cleanupEntry struct {
	name string
	fn   func()
}

// cleanupRegistry holds cleanup actions to run on interrupt. Actions run in
// LIFO order — later registrations (deeper into a flow) undo first. All access
// is mutex-guarded so registration from command goroutines and execution from
// the signal goroutine are safe.
//
// It also owns the interrupt itself (#89): the context that mutating work
// runs under, and the in-flight count that lets the handler wait for that
// work to stop before undoing it. The zero value is ready to use.
type cleanupRegistry struct {
	mu      sync.Mutex
	entries []*cleanupEntry

	ctx      context.Context    // cancelled by handleInterrupt
	cancel   context.CancelFunc //
	inflight int                // commands between begin and end
	idle     chan struct{}      // closed when inflight drops to 0, if someone waits
	cleaned  chan struct{}      // closed once handleInterrupt ran the cleanups
	once     sync.Once          // guards closing cleaned
}

// lazyInit sets up the interrupt state. Callers hold r.mu.
func (r *cleanupRegistry) lazyInit() {
	if r.ctx == nil {
		r.ctx, r.cancel = context.WithCancel(context.Background())
		r.cleaned = make(chan struct{})
	}
}

// context is the context mutating work runs under; handleInterrupt cancels it.
func (r *cleanupRegistry) context() context.Context {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.lazyInit()
	return r.ctx
}

// begin marks a mutating command as in flight and returns the func that ends
// it. After an interrupt, end does not return until handleInterrupt has run
// the cleanups, so the command cannot reach its own exit path (os.Exit) and
// cut them short. Call it as: defer reg.begin()().
func (r *cleanupRegistry) begin() (end func()) {
	r.mu.Lock()
	r.lazyInit()
	r.inflight++
	ctx, cleaned := r.ctx, r.cleaned
	r.mu.Unlock()
	return func() {
		r.mu.Lock()
		r.inflight--
		if r.inflight == 0 && r.idle != nil {
			close(r.idle)
			r.idle = nil
		}
		r.mu.Unlock()
		if ctx.Err() != nil {
			<-cleaned
		}
	}
}

// waitIdle waits up to timeout for every in-flight command to end. It reports
// whether they did.
func (r *cleanupRegistry) waitIdle(timeout time.Duration) bool {
	r.mu.Lock()
	if r.inflight == 0 {
		r.mu.Unlock()
		return true
	}
	if r.idle == nil {
		r.idle = make(chan struct{})
	}
	idle := r.idle
	r.mu.Unlock()
	select {
	case <-idle:
		return true
	case <-time.After(timeout):
		return false
	}
}

// handleInterrupt is what the signal handler does: cancel in-flight work,
// wait (up to wait) for it to return so the cleanups undo a settled state
// instead of racing it, then run the cleanups within budget. With nothing
// registered there is nothing to race, so it does not wait.
func (r *cleanupRegistry) handleInterrupt(wait, budget time.Duration) {
	r.mu.Lock()
	r.lazyInit()
	cancel, cleaned := r.cancel, r.cleaned
	r.mu.Unlock()

	cancel()
	if r.Len() > 0 && !r.waitIdle(wait) {
		fmt.Fprintln(os.Stderr, "cleanup: interrupted command still running, cleaning up anyway")
	}
	r.run(budget)
	r.once.Do(func() { close(cleaned) })
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

// run executes all registered entries LIFO within an overall timeout budget.
// Entries are taken off the registry under the lock before anything runs, so
// each runs at most once and a concurrent deregister cannot touch them. Each
// entry runs in a goroutine so a hanging one is abandoned at the deadline
// instead of blocking process exit; abandoned entries are noted on stderr.
func (r *cleanupRegistry) run(timeout time.Duration) {
	r.mu.Lock()
	pending := make([]*cleanupEntry, 0, len(r.entries))
	for i := len(r.entries) - 1; i >= 0; i-- {
		pending = append(pending, r.entries[i])
	}
	r.entries = nil
	r.mu.Unlock()

	deadline := time.Now().Add(timeout)
	for _, e := range pending {
		done := make(chan struct{})
		go func(fn func()) {
			defer close(done)
			fn()
		}(e.fn)
		select {
		case <-done:
		case <-time.After(time.Until(deadline)):
			fmt.Fprintf(os.Stderr, "cleanup: %q did not finish within budget, abandoning\n", e.name)
		}
	}
}
