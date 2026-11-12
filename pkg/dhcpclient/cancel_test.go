package dhcpclient

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// blockingClientExecutor makes the DHCP client run block until its context
// ends, like a udhcpc or dhclient waiting on a silent DHCP server.
type blockingClientExecutor struct {
	*mockExecutor
	clientRuns int
}

func (e *blockingClientExecutor) ExecuteContext(ctx context.Context, cmd string, args ...string) (string, error) {
	if cmd == "udhcpc" || cmd == "timeout" {
		e.clientRuns++
		<-ctx.Done()
		return "", errors.New("command cancelled: " + cmd)
	}
	return e.mockExecutor.ExecuteContext(ctx, cmd, args...)
}

// An interrupt during a DHCP attempt must end Acquire promptly, without
// sleeping RetryDelay and starting attempt 2 (#89).
func TestAcquire_CancelStopsTheAttemptAndSkipsTheRetry(t *testing.T) {
	for _, tc := range []struct {
		name   string
		udhcpc bool
		dhclnt bool
		iface  string
	}{
		{"udhcpc", true, false, "wlan0"},
		{"dhclient", false, true, "eth0"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tmp := t.TempDir()
			executor := &blockingClientExecutor{mockExecutor: newMockExecutor()}
			executor.hasCommands["udhcpc"] = tc.udhcpc
			executor.hasCommands["dhclient"] = tc.dhclnt
			manager := NewManager(executor, &mockLogger{})
			manager.hooksDir = t.TempDir()
			manager.runtimeDir = tmp
			manager.scriptDir = tmp + "/lib"

			ctx, cancel := context.WithCancel(context.Background())
			time.AfterFunc(50*time.Millisecond, cancel)

			start := time.Now()
			err := manager.Acquire(ctx, tc.iface, "")

			require.Error(t, err)
			assert.ErrorIs(t, err, context.Canceled)
			assert.Less(t, time.Since(start), time.Second)
			assert.Equal(t, 1, executor.clientRuns, "no second attempt after cancellation")
		})
	}
}

func TestAcquire_AlreadyCancelledStartsNoClient(t *testing.T) {
	executor := &blockingClientExecutor{mockExecutor: newMockExecutor()}
	executor.hasCommands["udhcpc"] = true
	manager := NewManager(executor, &mockLogger{})
	manager.runtimeDir = t.TempDir()
	manager.scriptDir = t.TempDir()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := manager.Acquire(ctx, "wlan0", "")

	assert.ErrorIs(t, err, context.Canceled)
	assert.Zero(t, executor.clientRuns)
}
