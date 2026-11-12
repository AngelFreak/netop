package wifi

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/angelfreak/net/pkg/netlink/fake"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// stallingExecutor stands in for an access point that never answers:
// `wpa_cli wait_event` blocks until its context ends, or, with
// noWaitEvent, is unsupported so the polling fallback runs and wpa_cli
// status never reports COMPLETED. It records every command with the time
// it was issued.
type stallingExecutor struct {
	mockSystemExecutor
	noWaitEvent bool
	mu          sync.Mutex
	issued      []issuedCmd
}

type issuedCmd struct {
	at  time.Time
	cmd string
}

func (e *stallingExecutor) record(cmd string, args []string) string {
	full := strings.TrimSpace(cmd + " " + strings.Join(args, " "))
	e.mu.Lock()
	e.issued = append(e.issued, issuedCmd{time.Now(), full})
	e.mu.Unlock()
	return full
}

func (e *stallingExecutor) ExecuteContext(ctx context.Context, cmd string, args ...string) (string, error) {
	full := e.record(cmd, args)
	switch {
	case strings.Contains(full, "wait_event") && e.noWaitEvent:
		return "", errors.New("wait_event: unknown command")
	case strings.Contains(full, "wait_event"):
		<-ctx.Done()
		return "", errors.New("command cancelled: wpa_cli")
	case strings.HasSuffix(full, "status"):
		return "wpa_state=SCANNING", nil
	}
	return "", nil
}

func (e *stallingExecutor) ExecuteWithTimeout(_ time.Duration, cmd string, args ...string) (string, error) {
	return e.ExecuteContext(context.Background(), cmd, args...)
}

func (e *stallingExecutor) Execute(cmd string, args ...string) (string, error) {
	return e.ExecuteContext(context.Background(), cmd, args...)
}

// after returns the commands issued after t.
func (e *stallingExecutor) after(t time.Time) []string {
	e.mu.Lock()
	defer e.mu.Unlock()
	var out []string
	for _, c := range e.issued {
		if c.at.After(t) {
			out = append(out, c.cmd)
		}
	}
	return out
}

type countingDHCPClient struct {
	mockDHCPClient
	acquires int
}

func (c *countingDHCPClient) Acquire(ctx context.Context, iface, hostname string) error {
	c.acquires++
	return nil
}

// An interrupt while waiting for the access point must end the connect
// promptly and start nothing new: no further polling and no DHCP. The only
// commands allowed afterwards tear down the half-made connection (#89).
func TestConnect_CancelDuringAssociationReturnsPromptly(t *testing.T) {
	for _, tc := range []struct {
		name        string
		noWaitEvent bool
	}{
		{"event wait", false},
		{"polling fallback", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			executor := &stallingExecutor{noWaitEvent: tc.noWaitEvent}
			dhcp := &countingDHCPClient{}
			manager := NewManager(executor, &mockLogger{}, "wlan0", dhcp)
			manager.linkMgr = &fake.LinkManager{}
			manager.addrMgr = &fake.AddrManager{}
			manager.routeMgr = &fake.RouteManager{}
			manager.runtimeDir = t.TempDir()
			manager.associationTimeout = time.Hour

			ctx, cancel := context.WithCancel(context.Background())
			var cancelledAt time.Time
			time.AfterFunc(300*time.Millisecond, func() { cancelledAt = time.Now(); cancel() })

			start := time.Now()
			err := manager.Connect(ctx, "Cafe", "password", "")

			require.Error(t, err)
			assert.ErrorIs(t, err, context.Canceled)
			assert.Less(t, time.Since(start), 1300*time.Millisecond)
			assert.Zero(t, dhcp.acquires, "no DHCP after cancellation")
			for _, cmd := range executor.after(cancelledAt) {
				assert.True(t, strings.Contains(cmd, "terminate") || strings.HasPrefix(cmd, "pkill"),
					"only teardown may run after cancellation, got %q", cmd)
			}
		})
	}
}

func TestConnect_AlreadyCancelledChangesNothing(t *testing.T) {
	executor := &stallingExecutor{}
	manager := NewManager(executor, &mockLogger{}, "wlan0", &countingDHCPClient{})
	links := &fake.LinkManager{}
	manager.linkMgr = links
	manager.addrMgr = &fake.AddrManager{}
	manager.routeMgr = &fake.RouteManager{}
	manager.runtimeDir = t.TempDir()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := manager.Connect(ctx, "Cafe", "password", "")

	assert.ErrorIs(t, err, context.Canceled)
	assert.Empty(t, executor.issued)
}
