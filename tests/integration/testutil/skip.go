//go:build integration

// Package testutil provides utilities for integration testing of network operations.
package testutil

import (
	"os"
	"os/exec"
	"testing"
)

// SkipIfNotRoot skips the test if not running as root.
// Most network operations require CAP_NET_ADMIN which typically means root.
func SkipIfNotRoot(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("skipping: test requires root privileges")
	}
}

// SkipIfNoHWSim skips the test if mac80211_hwsim kernel module is not available.
// This module provides virtual WiFi interfaces for testing.
func SkipIfNoHWSim(t *testing.T) {
	t.Helper()
	// Check if module is already loaded
	if _, err := os.Stat("/sys/module/mac80211_hwsim"); err == nil {
		return
	}
	// Try to load the module
	if err := exec.Command("modprobe", "mac80211_hwsim").Run(); err != nil {
		t.Skip("skipping: mac80211_hwsim kernel module not available")
	}
}

// SkipIfNoWireGuard skips the test if WireGuard kernel module is not available.
func SkipIfNoWireGuard(t *testing.T) {
	t.Helper()
	// Check if module is already loaded
	if _, err := os.Stat("/sys/module/wireguard"); err == nil {
		return
	}
	// Try to load the module
	if err := exec.Command("modprobe", "wireguard").Run(); err != nil {
		t.Skip("skipping: wireguard kernel module not available")
	}
}

// SkipIfNoNetNS skips the test if network namespaces are not supported.
func SkipIfNoNetNS(t *testing.T) {
	t.Helper()
	// Check if ip netns command works
	if err := exec.Command("ip", "netns", "list").Run(); err != nil {
		t.Skip("skipping: network namespaces not supported")
	}
}

// SkipIfMissingCmd skips the test if a required command is not available.
func SkipIfMissingCmd(t *testing.T, cmd string) {
	t.Helper()
	if _, err := exec.LookPath(cmd); err != nil {
		t.Skipf("skipping: required command %q not found in PATH", cmd)
	}
}

// RequireRoot fails the test immediately if not running as root.
// Use this instead of SkipIfNotRoot when root is absolutely required.
func RequireRoot(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Fatal("test requires root privileges")
	}
}

// RequireCommands fails the test if any of the required commands are missing.
func RequireCommands(t *testing.T, cmds ...string) {
	t.Helper()
	for _, cmd := range cmds {
		if _, err := exec.LookPath(cmd); err != nil {
			t.Fatalf("required command %q not found in PATH", cmd)
		}
	}
}
