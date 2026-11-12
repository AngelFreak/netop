//go:build integration

package testutil

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// TestNamespacesAreUniqueWithinABinary pins the fix for a PID-only namespace
// name. Every test in a package shares one PID, so the old
// "netop-test-<pid>" collided as soon as two namespaces were live at once —
// `ip netns add` fails with "File exists" — which is reachable via parallel
// subtests or a cleanup that did not run. Holding two at once is exactly what
// the old name could not do.
func TestNamespacesAreUniqueWithinABinary(t *testing.T) {
	SkipIfNotRoot(t)
	SkipIfNoNetNS(t)

	a := NewTestNamespace(t)
	b := NewTestNamespace(t)

	if a.Name == b.Name {
		t.Fatalf("two namespaces share a name (%q): a PID-only name collides", a.Name)
	}

	// Both must really exist at the same time, not merely differ by string.
	out, err := exec.Command("ip", "netns", "list").CombinedOutput()
	if err != nil {
		t.Fatalf("ip netns list: %v\noutput: %s", err, string(out))
	}
	for _, name := range []string{a.Name, b.Name} {
		if !strings.Contains(string(out), name) {
			t.Errorf("namespace %q missing from `ip netns list`:\n%s", name, string(out))
		}
	}

	// And each must be independently usable.
	for _, ns := range []*TestNamespace{a, b} {
		if err := ns.Exec("ip", "link", "show", "lo"); err != nil {
			t.Errorf("namespace %q unusable: %v", ns.Name, err)
		}
	}
}

// TestExecStdinFeedsTheCommand covers the seam the wg private-key fix relies
// on: without a working stdin, `wg set ... private-key /dev/stdin` silently
// has nothing to read.
func TestExecStdinFeedsTheCommand(t *testing.T) {
	SkipIfNotRoot(t)
	SkipIfNoNetNS(t)
	SkipIfMissingCmd(t, "cat")

	ns := NewTestNamespace(t)
	if err := ns.ExecStdin("hello\n", "grep", "-q", "hello"); err != nil {
		t.Errorf("stdin did not reach the command: %v", err)
	}
	// A non-match must still surface as an error, so the check above is real.
	if err := ns.ExecStdin("hello\n", "grep", "-q", "goodbye"); err == nil {
		t.Error("expected grep to fail on a non-matching stdin")
	}
}

// TestHWSimGuardSkipsRatherThanFails is the regression guard for the
// integration job's long-hidden failure mode. The job could not run a test
// for months (a dependency-install abort); once unblocked, three tests failed
// on a runner where mac80211_hwsim loads and presents an interface whose every
// operation returns "Network is down (-100)". That surfaced as an opaque
// `exit status 156`/`237` from iw/hostapd.
//
// Missing or broken infrastructure is a missing capability, not a defect in
// the code under test, and the workflow states tests "skip gracefully if
// capabilities are missing". LoadHWSim must therefore skip, never fail. A
// Skip*/Fatal* both stop the calling goroutine, so the only portable way to
// tell them apart is to observe that the test did not fail: on a runner with
// working radios we get radios, and on one without we get skipped here.
func TestHWSimGuardSkipsRatherThanFails(t *testing.T) {
	SkipIfNotRoot(t)

	radios := LoadHWSim(t, 1)

	// Reached only when the guard judged the radio usable — so it must be.
	if len(radios) < 1 {
		t.Fatal("LoadHWSim returned no radios without skipping")
	}
	if out, err := exec.Command("iw", "dev", radios[0].Interface, "info").CombinedOutput(); err != nil {
		t.Errorf("LoadHWSim handed back an unusable radio %q instead of skipping: %v\noutput: %s",
			radios[0].Interface, err, string(out))
	}
}

// TestRunDoesNotReturnItsThreadToThePool pins the fix for Run handing a
// thread that is still inside the test namespace back to Go's scheduler.
// Run setns()es a locked thread; if it unlocks before the goroutine exits,
// that thread is reused by later goroutines, and an `exec.Command("ip", "link",
// "add", ...)` forked from it creates the link inside a stale test namespace.
// That broke AddVethPair in whichever test ran next ("failed to move
// veth-ns-dns to namespace").
//
// A goroutine that exits while still locked has its thread terminated, except
// the main thread (tid == pid), which the runtime parks forever instead. So
// across several Runs at most one may land on the main thread, and every
// other thread must exit. Without the fix, threads survive or the main thread
// is reused, and this fails either way.
func TestRunDoesNotReturnItsThreadToThePool(t *testing.T) {
	SkipIfNotRoot(t)
	SkipIfNoNetNS(t)

	ns := NewTestNamespace(t)
	pid := unix.Getpid()
	onMain := 0
	for i := 0; i < 3; i++ {
		var tid int
		if err := ns.Run(func() { tid = unix.Gettid() }); err != nil {
			t.Fatalf("Run: %v", err)
		}
		if tid == pid {
			onMain++
			continue
		}
		// The thread exits just after Run's result is sent, so wait for it.
		task := fmt.Sprintf("/proc/self/task/%d", tid)
		deadline := time.Now().Add(5 * time.Second)
		for {
			if _, err := os.Stat(task); os.IsNotExist(err) {
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("thread %d that entered namespace %s is still alive: Run returned it to the scheduler", tid, ns.Name)
			}
			time.Sleep(10 * time.Millisecond)
		}
	}
	if onMain > 1 {
		t.Fatalf("Run used the main thread %d times: it was returned to the scheduler instead of parked", onMain)
	}
}
