# Integration Tests Design

**Issue**: #9 - Add integration tests with real network operations
**Date**: 2026-01-15
**Status**: Approved

## Overview

Add integration tests that verify real network operations work correctly. Tests run locally with `sudo` and optionally in CI with proper kernel modules and capabilities.

## Goals

- Test real network operations (WiFi, VPN, DNS, MAC, hotspot) against actual system interfaces
- Catch issues that mocks miss
- Build confidence in releases
- Run in CI automatically on PRs

## Design Decisions

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Test scope | Full (WiFi, VPN, DNS, MAC, hotspot) | Comprehensive coverage |
| WiFi simulation | mac80211_hwsim kernel module | Standard approach, works in CI |
| Test structure | Hybrid (shared testutil + per-package tests) | Go conventions + shared setup code |
| CI integration | Optional with graceful skip | Tests skip if capabilities unavailable |

## Directory Structure

```
tests/
└── integration/
    └── testutil/
        ├── namespace.go      # Network namespace creation/teardown
        ├── hwsim.go          # mac80211_hwsim module management
        ├── hostapd.go        # Test AP management
        ├── dnsmasq.go        # Test DHCP server
        ├── wireguard.go      # WireGuard peer simulation
        └── skip.go           # Capability detection & skip helpers

pkg/
├── network/
│   └── network_integration_test.go   # DNS, MAC, IP, routes
├── wifi/
│   └── wifi_integration_test.go      # Scan, connect, disconnect
├── vpn/
│   └── vpn_integration_test.go       # WireGuard connect/disconnect
├── hotspot/
│   └── hotspot_integration_test.go   # AP mode, client management
└── dhcp/
    └── dhcp_integration_test.go      # DHCP server for hotspot
```

## Build Tags

All integration tests use `//go:build integration` so they're skipped by default:

```bash
# Run unit tests only (default)
go test ./...

# Run integration tests (requires root)
sudo go test -tags=integration ./...

# Run both
sudo go test -tags=integration ./...
```

## Test Utilities

### namespace.go - Network Namespace Isolation

```go
// Creates isolated network namespace for each test
// Prevents tests from affecting host network
type TestNamespace struct {
    Name    string
    Cleanup func()
}

func NewTestNamespace(t *testing.T) *TestNamespace
func (ns *TestNamespace) Run(fn func()) error  // Execute in namespace
```

### hwsim.go - Virtual WiFi Interfaces

```go
// Loads mac80211_hwsim kernel module, creates virtual radios
// Each radio gets a wlanX interface that behaves like real hardware
type HWSimRadio struct {
    PHY       string  // phy0, phy1, etc.
    Interface string  // wlan0, wlan1, etc.
}

func LoadHWSim(t *testing.T, numRadios int) []*HWSimRadio
func UnloadHWSim()
```

### hostapd.go - Test Access Point

```go
// Starts hostapd on a hwsim interface to create test AP
type TestAP struct {
    SSID      string
    PSK       string
    Interface string
    Channel   int
}

func StartTestAP(t *testing.T, radio *HWSimRadio, cfg TestAPConfig) *TestAP
func (ap *TestAP) Stop()
```

### skip.go - Graceful Capability Detection

```go
func SkipIfNotRoot(t *testing.T)
func SkipIfNoHWSim(t *testing.T)      // mac80211_hwsim unavailable
func SkipIfNoWireGuard(t *testing.T)  // wireguard module unavailable
func SkipIfMissingCmd(t *testing.T, cmd string)  // hostapd, dnsmasq, etc.
```

## Test Scenarios

### pkg/network/network_integration_test.go

- Set DNS servers, verify `/etc/resolv.conf` changes (in namespace)
- Change MAC address, verify with `ip link show`
- Set static IP and gateway, verify routes
- Flush routes, verify cleanup

### pkg/wifi/wifi_integration_test.go

- Scan for test AP created by hostapd, verify SSID appears
- Connect to WPA2 network with PSK, verify association
- Connect to open network, verify association
- Disconnect, verify state cleanup
- BSSID pinning to specific AP

### pkg/vpn/vpn_integration_test.go

- Create WireGuard interface, verify `ip link show type wireguard`
- Set WireGuard config with peers, verify with `wg show`
- Set interface IP and bring up, verify connectivity
- Disconnect and cleanup, verify interface removed
- Verify active VPN state file tracking

### pkg/hotspot/hotspot_integration_test.go

- Start AP on hwsim interface via hostapd, verify interface in AP mode
- Start DHCP server via dnsmasq, verify listening
- Simulate client connection from second hwsim radio
- Verify client gets DHCP lease
- Stop hotspot, verify cleanup

### pkg/dhcp/dhcp_integration_test.go

- Start dnsmasq with test config
- Request lease from namespace, verify IP assigned
- Verify lease file written correctly

## Example Test Implementation

```go
//go:build integration

package wifi

import (
    "testing"
    "github.com/angelfreak/net/tests/integration/testutil"
    "github.com/stretchr/testify/assert"
    "github.com/stretchr/testify/require"
)

func TestWiFiConnect_Integration(t *testing.T) {
    testutil.SkipIfNotRoot(t)
    testutil.SkipIfNoHWSim(t)
    testutil.SkipIfMissingCmd(t, "hostapd")
    testutil.SkipIfMissingCmd(t, "wpa_supplicant")

    // Create isolated network namespace
    ns := testutil.NewTestNamespace(t)
    defer ns.Cleanup()

    // Load virtual WiFi radios
    radios := testutil.LoadHWSim(t, 2)

    // Start test AP on first radio
    ap := testutil.StartTestAP(t, radios[0], testutil.TestAPConfig{
        SSID: "TestNetwork",
        PSK:  "testpassword123",
    })
    defer ap.Stop()

    // Test scan finds our AP
    ns.Run(func() {
        manager := NewManager(executor, logger)
        manager.SetInterface(radios[1].Interface)

        networks, err := manager.Scan()
        require.NoError(t, err)
        assert.Contains(t, networks, "TestNetwork")

        // Test connect
        err = manager.Connect("TestNetwork", "testpassword123", "")
        require.NoError(t, err)

        // Verify connected state
        conns, _ := manager.ListConnections()
        assert.Len(t, conns, 1)
        assert.Equal(t, "TestNetwork", conns[0].SSID)
    })
}
```

## CI Integration

**.github/workflows/integration.yml**:

```yaml
name: Integration Tests
on:
  push:
    branches: [master]
  pull_request:

jobs:
  integration:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Set up Go
        uses: actions/setup-go@v5
        with:
          go-version: '1.22'

      - name: Install dependencies
        run: |
          sudo apt-get update
          sudo apt-get install -y hostapd dnsmasq iw wireless-tools wireguard-tools

      - name: Load kernel modules
        run: |
          sudo modprobe mac80211_hwsim radios=4
          sudo modprobe wireguard

      - name: Run integration tests
        run: sudo go test -tags=integration -v ./...
```

## Graceful Degradation

- Tests skip with clear message if capabilities unavailable
- Partial runs allowed on systems without full support
- Regular `go test ./...` runs fast unit tests only

## Implementation Order

1. `tests/integration/testutil/skip.go` - Capability detection
2. `tests/integration/testutil/namespace.go` - Network namespace isolation
3. `pkg/network/network_integration_test.go` - DNS, MAC, IP tests (simplest)
4. `tests/integration/testutil/wireguard.go` - WireGuard helpers
5. `pkg/vpn/vpn_integration_test.go` - VPN tests
6. `tests/integration/testutil/hwsim.go` - WiFi simulation
7. `tests/integration/testutil/hostapd.go` - Test AP
8. `pkg/wifi/wifi_integration_test.go` - WiFi tests
9. `tests/integration/testutil/dnsmasq.go` - DHCP server
10. `pkg/hotspot/hotspot_integration_test.go` - Hotspot tests
11. `pkg/dhcp/dhcp_integration_test.go` - DHCP server tests
12. `.github/workflows/integration.yml` - CI workflow
