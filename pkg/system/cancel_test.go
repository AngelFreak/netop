package system

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSleep_ReturnsAfterTheDuration(t *testing.T) {
	start := time.Now()
	require.NoError(t, Sleep(context.Background(), 20*time.Millisecond))
	assert.GreaterOrEqual(t, time.Since(start), 20*time.Millisecond)
}

func TestSleep_ReturnsPromptlyWhenCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(10*time.Millisecond, cancel)

	start := time.Now()
	err := Sleep(ctx, time.Hour)

	assert.ErrorIs(t, err, context.Canceled)
	assert.Less(t, time.Since(start), time.Second)
}

// ctxRecorder is an executor that blocks in ExecuteContext until its context
// is done, the way a real wpa_cli wait_event or udhcpc run would.
type ctxRecorder struct {
	testExecutor
	deadline time.Time
	hadDL    bool
}

func (e *ctxRecorder) ExecuteContext(ctx context.Context, cmd string, args ...string) (string, error) {
	e.deadline, e.hadDL = ctx.Deadline()
	<-ctx.Done()
	return "", ctx.Err()
}

func TestExecuteWithin_StopsWhenTheParentIsCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(10*time.Millisecond, cancel)
	e := &ctxRecorder{}

	start := time.Now()
	_, err := ExecuteWithin(ctx, e, time.Hour, "wpa_cli", "status")

	assert.True(t, errors.Is(err, context.Canceled))
	assert.Less(t, time.Since(start), time.Second)
}

func TestExecuteWithin_AppliesTheTimeout(t *testing.T) {
	e := &ctxRecorder{}
	before := time.Now()

	_, err := ExecuteWithin(context.Background(), e, 20*time.Millisecond, "udhcpc")

	assert.ErrorIs(t, err, context.DeadlineExceeded)
	require.True(t, e.hadDL)
	assert.WithinDuration(t, before.Add(20*time.Millisecond), e.deadline, 15*time.Millisecond)
}

// A context cancelled before the call must not start the command at all.
func TestExecuteWithin_DoesNotStartAfterCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	e := &testExecutor{}

	_, err := ExecuteWithin(ctx, e, time.Second, "ip", "link")

	assert.ErrorIs(t, err, context.Canceled)
	assert.Empty(t, e.executedCommands)
}
