//go:build integration

package testutil

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// HWSimRadio represents a virtual WiFi radio created by mac80211_hwsim.
type HWSimRadio struct {
	PHY       string // phy name (e.g., "phy0")
	Interface string // interface name (e.g., "wlan0")
	Index     int    // radio index
}

// hwsimLoaded tracks whether we've loaded the module in this test run
var hwsimLoaded bool

// LoadHWSim loads the mac80211_hwsim kernel module and returns the created radios.
// The module is loaded with the specified number of radios.
func LoadHWSim(t *testing.T, numRadios int) []*HWSimRadio {
	t.Helper()
	SkipIfNotRoot(t)
	SkipIfNoHWSim(t)

	// If module is already loaded, unload it first to get a clean state
	if isHWSimLoaded() {
		if err := exec.Command("modprobe", "-r", "mac80211_hwsim").Run(); err != nil {
			t.Logf("Warning: failed to unload existing mac80211_hwsim: %v", err)
		}
		time.Sleep(100 * time.Millisecond)
	}

	// Load the module with requested number of radios
	err := exec.Command("modprobe", "mac80211_hwsim", fmt.Sprintf("radios=%d", numRadios)).Run()
	if err != nil {
		t.Fatalf("failed to load mac80211_hwsim: %v", err)
	}
	hwsimLoaded = true

	// Register cleanup to unload module
	t.Cleanup(func() {
		UnloadHWSim()
	})

	// Wait for interfaces to appear
	time.Sleep(500 * time.Millisecond)

	// Find the created radios
	radios, err := findHWSimRadios(numRadios)
	if err != nil {
		t.Fatalf("failed to find hwsim radios: %v", err)
	}

	if len(radios) < numRadios {
		t.Fatalf("expected %d radios, found %d", numRadios, len(radios))
	}

	return radios
}

// UnloadHWSim unloads the mac80211_hwsim kernel module.
func UnloadHWSim() {
	if hwsimLoaded {
		_ = exec.Command("modprobe", "-r", "mac80211_hwsim").Run()
		hwsimLoaded = false
	}
}

// isHWSimLoaded checks if mac80211_hwsim module is currently loaded.
func isHWSimLoaded() bool {
	_, err := os.Stat("/sys/module/mac80211_hwsim")
	return err == nil
}

// findHWSimRadios finds all hwsim radios and their associated interfaces.
func findHWSimRadios(expected int) ([]*HWSimRadio, error) {
	var radios []*HWSimRadio

	// Look through /sys/class/ieee80211 for hwsim phys
	phyDir := "/sys/class/ieee80211"
	entries, err := os.ReadDir(phyDir)
	if err != nil {
		return nil, fmt.Errorf("failed to read %s: %v", phyDir, err)
	}

	for i, entry := range entries {
		phyName := entry.Name()

		// Check if this is a hwsim phy by looking for hwsim in the driver path
		driverPath := filepath.Join(phyDir, phyName, "device", "driver")
		if target, err := os.Readlink(driverPath); err == nil {
			if !strings.Contains(target, "hwsim") {
				continue
			}
		}

		// Find the interface for this phy
		ifaceName, err := findInterfaceForPhy(phyName)
		if err != nil {
			continue
		}

		radios = append(radios, &HWSimRadio{
			PHY:       phyName,
			Interface: ifaceName,
			Index:     i,
		})

		if len(radios) >= expected {
			break
		}
	}

	return radios, nil
}

// findInterfaceForPhy finds the network interface associated with a phy.
func findInterfaceForPhy(phyName string) (string, error) {
	// Look through /sys/class/net for interfaces with this phy
	netDir := "/sys/class/net"
	entries, err := os.ReadDir(netDir)
	if err != nil {
		return "", err
	}

	for _, entry := range entries {
		ifaceName := entry.Name()
		phyPath := filepath.Join(netDir, ifaceName, "phy80211", "name")

		if data, err := os.ReadFile(phyPath); err == nil {
			if strings.TrimSpace(string(data)) == phyName {
				return ifaceName, nil
			}
		}
	}

	return "", fmt.Errorf("no interface found for phy %s", phyName)
}

// SetInterfaceMode sets the mode of a wireless interface (e.g., "managed", "monitor", "ap").
func SetInterfaceMode(t *testing.T, ifaceName, mode string) error {
	t.Helper()

	// Bring interface down
	if err := exec.Command("ip", "link", "set", ifaceName, "down").Run(); err != nil {
		return fmt.Errorf("failed to bring down %s: %v", ifaceName, err)
	}

	// Set mode
	if err := exec.Command("iw", "dev", ifaceName, "set", "type", mode).Run(); err != nil {
		return fmt.Errorf("failed to set %s mode to %s: %v", ifaceName, mode, err)
	}

	// Bring interface up
	if err := exec.Command("ip", "link", "set", ifaceName, "up").Run(); err != nil {
		return fmt.Errorf("failed to bring up %s: %v", ifaceName, err)
	}

	return nil
}

// MoveRadioToNamespace moves a hwsim radio's interface to a network namespace.
func (r *HWSimRadio) MoveToNamespace(ns *TestNamespace) error {
	// Move the interface to the namespace
	if err := ns.MoveInterface(r.Interface); err != nil {
		return fmt.Errorf("failed to move interface %s to namespace: %v", r.Interface, err)
	}

	// Bring it up in the namespace
	if err := ns.Exec("ip", "link", "set", r.Interface, "up"); err != nil {
		return fmt.Errorf("failed to bring up %s in namespace: %v", r.Interface, err)
	}

	return nil
}

// Scan performs a WiFi scan on this radio's interface and returns the output.
func (r *HWSimRadio) Scan(ns *TestNamespace) (string, error) {
	if ns != nil {
		return ns.ExecOutput("iw", "dev", r.Interface, "scan")
	}
	output, err := exec.Command("iw", "dev", r.Interface, "scan").CombinedOutput()
	return string(output), err
}

// GetInfo returns information about the radio's interface.
func (r *HWSimRadio) GetInfo(ns *TestNamespace) (string, error) {
	if ns != nil {
		return ns.ExecOutput("iw", "dev", r.Interface, "info")
	}
	output, err := exec.Command("iw", "dev", r.Interface, "info").CombinedOutput()
	return string(output), err
}
