//go:build integration

package testutil

import (
	"fmt"
	"os/exec"
	"runtime"
	"testing"

	"golang.org/x/sys/unix"
)

// TestNamespace represents an isolated network namespace for testing.
// Each test gets its own namespace to avoid affecting the host network.
type TestNamespace struct {
	Name string
	t    *testing.T
}

// NewTestNamespace creates a new network namespace for testing.
// The namespace is automatically cleaned up when the test finishes.
func NewTestNamespace(t *testing.T) *TestNamespace {
	t.Helper()
	SkipIfNotRoot(t)
	SkipIfNoNetNS(t)

	// Generate unique namespace name based on test name
	name := fmt.Sprintf("netop-test-%d", unix.Getpid())

	// Create the namespace
	if err := exec.Command("ip", "netns", "add", name).Run(); err != nil {
		t.Fatalf("failed to create network namespace %s: %v", name, err)
	}

	ns := &TestNamespace{
		Name: name,
		t:    t,
	}

	// Register cleanup
	t.Cleanup(ns.cleanup)

	// Bring up loopback in the namespace
	if err := ns.Exec("ip", "link", "set", "lo", "up"); err != nil {
		t.Fatalf("failed to bring up loopback in namespace: %v", err)
	}

	return ns
}

// cleanup removes the network namespace.
func (ns *TestNamespace) cleanup() {
	_ = exec.Command("ip", "netns", "del", ns.Name).Run()
}

// Exec runs a command inside the network namespace.
func (ns *TestNamespace) Exec(name string, args ...string) error {
	cmdArgs := append([]string{"netns", "exec", ns.Name, name}, args...)
	cmd := exec.Command("ip", cmdArgs...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("command %q in namespace %s failed: %v\noutput: %s",
			name, ns.Name, err, string(output))
	}
	return nil
}

// ExecOutput runs a command inside the network namespace and returns its output.
func (ns *TestNamespace) ExecOutput(name string, args ...string) (string, error) {
	cmdArgs := append([]string{"netns", "exec", ns.Name, name}, args...)
	cmd := exec.Command("ip", cmdArgs...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("command %q in namespace %s failed: %v\noutput: %s",
			name, ns.Name, err, string(output))
	}
	return string(output), nil
}

// Run executes a function inside the network namespace.
// This uses setns to switch the current thread to the namespace.
// Note: The function runs in a locked OS thread to ensure namespace isolation.
func (ns *TestNamespace) Run(fn func()) error {
	// Get the namespace file descriptor
	nsPath := fmt.Sprintf("/var/run/netns/%s", ns.Name)

	errCh := make(chan error, 1)

	go func() {
		// Lock this goroutine to its OS thread so setns only affects this thread
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()

		// Open the namespace
		fd, err := unix.Open(nsPath, unix.O_RDONLY|unix.O_CLOEXEC, 0)
		if err != nil {
			errCh <- fmt.Errorf("failed to open namespace %s: %v", nsPath, err)
			return
		}
		defer unix.Close(fd)

		// Switch to the namespace
		if err := unix.Setns(fd, unix.CLONE_NEWNET); err != nil {
			errCh <- fmt.Errorf("failed to setns to %s: %v", ns.Name, err)
			return
		}

		// Run the function in the namespace
		fn()
		errCh <- nil
	}()

	return <-errCh
}

// AddVethPair creates a veth pair with one end in this namespace and one in the host.
// Returns the names of the host-side and namespace-side interfaces.
func (ns *TestNamespace) AddVethPair(hostName, nsName string) error {
	// Create veth pair in host namespace
	if err := exec.Command("ip", "link", "add", hostName, "type", "veth", "peer", "name", nsName).Run(); err != nil {
		return fmt.Errorf("failed to create veth pair: %v", err)
	}

	// Move one end to the test namespace
	if err := exec.Command("ip", "link", "set", nsName, "netns", ns.Name).Run(); err != nil {
		// Cleanup the host side
		_ = exec.Command("ip", "link", "del", hostName).Run()
		return fmt.Errorf("failed to move %s to namespace %s: %v", nsName, ns.Name, err)
	}

	return nil
}

// MoveInterface moves an existing interface into this namespace.
func (ns *TestNamespace) MoveInterface(ifname string) error {
	if err := exec.Command("ip", "link", "set", ifname, "netns", ns.Name).Run(); err != nil {
		return fmt.Errorf("failed to move interface %s to namespace %s: %v", ifname, ns.Name, err)
	}
	return nil
}
