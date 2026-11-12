package network

import (
	"context"
	"testing"
	"time"

	"github.com/angelfreak/net/pkg/netlink/fake"
	"github.com/angelfreak/net/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// blockingDHCPClient models a DHCP server that never answers: Acquire
// blocks until its context ends.
type blockingDHCPClient struct {
	mockDHCPClient
	acquires int
}

func (c *blockingDHCPClient) Acquire(ctx context.Context, iface, hostname string) error {
	c.acquires++
	<-ctx.Done()
	return ctx.Err()
}

// ctxWiFi records the context a configured connect hands to the WiFi manager.
type ctxWiFi struct {
	mockWiFiManagerImpl
	got context.Context
}

func (w *ctxWiFi) Connect(ctx context.Context, ssid, password, hostname string) error {
	w.got = ctx
	return nil
}

func (w *ctxWiFi) ConnectWithBSSID(ctx context.Context, ssid, password, bssid, hostname string) error {
	w.got = ctx
	return nil
}

func cancelAfter(d time.Duration) context.Context {
	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(d, cancel)
	return ctx
}

// An interrupt while a wired connect waits for a lease ends it promptly. The
// error is the interruption, not a diagnosis of a silent DHCP server, and DNS
// is not taken over afterwards (#89).
func TestConnectToConfiguredNetwork_CancelDuringWiredDHCP(t *testing.T) {
	manager := newSeamTestManager(t)
	manager.hasCarrierFn = func(string) bool { return true }
	dhcp := &blockingDHCPClient{}
	manager.dhcpClient = dhcp

	start := time.Now()
	err := manager.ConnectToConfiguredNetwork(cancelAfter(100*time.Millisecond),
		&types.NetworkConfig{Interface: "eth0", DNS: []string{"dhcp"}}, "", nil)

	require.Error(t, err)
	assert.ErrorIs(t, err, context.Canceled)
	assert.Less(t, time.Since(start), time.Second)
	assert.Equal(t, 1, dhcp.acquires)
	assert.NotContains(t, err.Error(), "DHCP server", "an interrupt is not a silent DHCP server")
	assert.False(t, manager.isDNSOwned(), "DNS must not be taken over after cancellation")
}

func TestConnectToConfiguredNetwork_CancelDuringCarrierWait(t *testing.T) {
	manager := newSeamTestManager(t)
	manager.hasCarrierFn = func(string) bool { return false } // cable never comes up
	dhcp := &blockingDHCPClient{}
	manager.dhcpClient = dhcp

	start := time.Now()
	err := manager.ConnectToConfiguredNetwork(cancelAfter(100*time.Millisecond),
		&types.NetworkConfig{Interface: "eth0"}, "", nil)

	assert.ErrorIs(t, err, context.Canceled)
	assert.Less(t, time.Since(start), time.Second, "the 5s carrier wait must not run out")
	assert.Zero(t, dhcp.acquires, "no DHCP after cancellation")
}

func TestConnectToConfiguredNetwork_PassesItsContextToTheWiFiConnect(t *testing.T) {
	for _, tc := range []struct {
		name   string
		apAddr string
	}{{"ssid", ""}, {"pinned bssid", "aa:bb:cc:dd:ee:ff"}} {
		t.Run(tc.name, func(t *testing.T) {
			manager := newSeamTestManager(t)
			wifi := &ctxWiFi{}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			_ = manager.ConnectToConfiguredNetwork(ctx,
				&types.NetworkConfig{Interface: "wlan0", SSID: "Cafe", ApAddr: tc.apAddr}, "", wifi)

			require.NotNil(t, wifi.got)
			cancel()
			assert.Error(t, wifi.got.Err(), "the WiFi connect must run under the caller's context")
		})
	}
}

func TestConnectToConfiguredNetwork_AlreadyCancelledChangesNothing(t *testing.T) {
	manager := newSeamTestManager(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := manager.ConnectToConfiguredNetwork(ctx,
		&types.NetworkConfig{Interface: "eth0", MAC: "random"}, "", nil)

	assert.ErrorIs(t, err, context.Canceled)
	links := manager.linkMgr.(*fake.LinkManager)
	assert.Empty(t, links.SetMACCalls, "no MAC change")
	assert.Empty(t, links.Upped, "no link change")
}
