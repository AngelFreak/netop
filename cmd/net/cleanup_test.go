package main

import (
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestCleanupRegistry_LIFOOrder(t *testing.T) {
	r := &cleanupRegistry{}
	var order []string
	r.register("first", func() { order = append(order, "first") })
	r.register("second", func() { order = append(order, "second") })
	r.register("third", func() { order = append(order, "third") })

	r.run(time.Second)

	// LIFO: last registered runs first.
	assert.Equal(t, []string{"third", "second", "first"}, order)
}

func TestCleanupRegistry_RunsAtMostOnce(t *testing.T) {
	r := &cleanupRegistry{}
	calls := 0
	r.register("once", func() { calls++ })

	r.run(time.Second)
	r.run(time.Second) // second run must not re-invoke the entry
	assert.Equal(t, 1, calls)
}

func TestCleanupRegistry_DeregisterRemoves(t *testing.T) {
	r := &cleanupRegistry{}
	called := false
	deregister := r.register("gone", func() { called = true })
	assert.Equal(t, 1, r.Len())

	deregister()
	assert.Equal(t, 0, r.Len())

	r.run(time.Second)
	assert.False(t, called, "deregistered entry must not run")
}

func TestCleanupRegistry_DeregisterAfterRunIsSafe(t *testing.T) {
	r := &cleanupRegistry{}
	calls := 0
	deregister := r.register("entry", func() { calls++ })

	r.run(time.Second)
	// Deregistering after the run has already consumed the entry must be a
	// no-op, not a panic or a double-decrement.
	deregister()
	assert.Equal(t, 1, calls)
	assert.Equal(t, 0, r.Len())
}

func TestCleanupRegistry_ConcurrentRegisterAndRun(t *testing.T) {
	// Run with -race to catch unsynchronized access to the registry.
	r := &cleanupRegistry{}
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			deregister := r.register("concurrent", func() {})
			deregister()
		}()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		r.run(time.Second)
	}()
	wg.Wait()
}

func TestCleanupRegistry_TimeoutAbandonsHangingEntry(t *testing.T) {
	r := &cleanupRegistry{}
	release := make(chan struct{})
	defer close(release)
	r.register("hangs", func() { <-release }) // blocks past the budget

	start := time.Now()
	r.run(50 * time.Millisecond)
	elapsed := time.Since(start)

	// run must return near the budget, not block on the hanging entry.
	assert.Less(t, elapsed, 500*time.Millisecond,
		"run should abandon a hanging entry at the timeout, not wait for it")
}
