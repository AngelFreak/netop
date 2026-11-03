//go:build integration

package testutil

import (
	"os/exec"
	"strings"
	"testing"
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
