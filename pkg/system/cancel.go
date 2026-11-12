package system

import (
	"context"
	"fmt"
	"time"

	"github.com/angelfreak/net/pkg/types"
)

// Sleep waits for d, or until ctx is done, whichever comes first. It returns
// ctx.Err() when cancelled, so a retry or poll loop can stop on interrupt
// instead of sleeping through it.
func Sleep(ctx context.Context, d time.Duration) error {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-timer.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// ExecuteWithin runs cmd under ctx, limited to timeout: the context-aware
// form of ExecuteWithTimeout. A cancelled ctx starts nothing, and cancelling
// it kills a running command. When ctx ended the command, the error wraps
// ctx's error, so callers can tell an interrupt or timeout from a failure
// with errors.Is.
func ExecuteWithin(ctx context.Context, e types.SystemExecutor, timeout time.Duration, cmd string, args ...string) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	out, err := e.ExecuteContext(cctx, cmd, args...)
	if err != nil {
		if ctxErr := cctx.Err(); ctxErr != nil {
			return out, fmt.Errorf("%s: %w", cmd, ctxErr)
		}
	}
	return out, err
}
