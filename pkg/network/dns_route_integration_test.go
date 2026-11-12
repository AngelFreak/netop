//go:build integration && linux

package network

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"testing"

	vnl "github.com/vishvananda/netlink"

	"github.com/angelfreak/net/pkg/system"
	"github.com/angelfreak/net/tests/integration/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The kernel's own route lookup must agree with PinDNSRoutes: a DHCP DNS
// server that a local bridge subnet captures (172.18.4.50 under a Docker-style
// 172.18.0.0/16) leaves through the uplink once the manager has run.
//
// Failures inside ns.Run are recorded and asserted afterwards: t.Fatal there
// would deadlock the harness (see pkg/netlink/route_integration_test.go).
func TestPinDNSRoutes_Integration_KernelRoutesShadowedDNSViaUplink(t *testing.T) {
	testutil.SkipIfNotRoot(t)
	ns := testutil.NewTestNamespace(t)

	resolvConf := filepath.Join(t.TempDir(), "resolv.conf")
	require.NoError(t, os.WriteFile(resolvConf, []byte("nameserver 172.18.4.50\n"), 0644))
	dnsServer := net.ParseIP("172.18.4.50")

	var before, after string
	var opErr error
	egress := func() (string, error) {
		routes, err := vnl.RouteGet(dnsServer)
		if err != nil {
			return "", err
		}
		if len(routes) == 0 {
			return "", fmt.Errorf("no route to %s", dnsServer)
		}
		link, err := vnl.LinkByIndex(routes[0].LinkIndex)
		if err != nil {
			return "", err
		}
		return link.Attrs().Name, nil
	}
	addDummy := func(name, cidr string) error {
		link := &vnl.Dummy{LinkAttrs: vnl.LinkAttrs{Name: name}}
		if err := vnl.LinkAdd(link); err != nil {
			return err
		}
		if err := vnl.LinkSetUp(link); err != nil {
			return err
		}
		addr, err := vnl.ParseAddr(cidr)
		if err != nil {
			return err
		}
		return vnl.AddrAdd(link, addr)
	}

	runErr := ns.Run(func() {
		if opErr = addDummy("uplink0", "100.68.8.2/21"); opErr != nil {
			return
		}
		if opErr = addDummy("br-docker", "172.18.0.1/16"); opErr != nil {
			return
		}
		logger := &testLogger{t: t}
		manager := NewManager(system.NewExecutor(logger, false), logger, nil)
		manager.resolvConfPath = resolvConf
		if opErr = manager.routeMgr.SetDefaultForIface("uplink0", "100.68.8.1", 600); opErr != nil {
			return
		}
		if before, opErr = egress(); opErr != nil {
			return
		}
		manager.PinDNSRoutes("uplink0")
		after, opErr = egress()
	})
	require.NoError(t, runErr)
	require.NoError(t, opErr)

	assert.Equal(t, "br-docker", before, "precondition: the bridge subnet captures the DNS server")
	assert.Equal(t, "uplink0", after)
}
