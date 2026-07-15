//go:build integration && linux

package netlink

import (
	"testing"

	vnl "github.com/vishvananda/netlink"

	"github.com/angelfreak/net/tests/integration/testutil"
)

// TestRouteManagerInNamespace exercises the real netlink RouteManager against
// the kernel inside an isolated network namespace. It verifies the crux parity
// requirement: BOTH gateway default routes AND device-only default routes
// (e.g. `default dev wg0`, Gw==nil) round-trip correctly. The device-only case
// is the motivating bug the migration exists to fix.
//
// The namespace harness (testutil.NewTestNamespace + Run) itself shells out to
// `ip netns`/`ip link`; this test proves the migrated netlink production code
// works under that same Setns(CLONE_NEWNET) isolation (Tier-1 exit criterion).
func TestRouteManagerInNamespace(t *testing.T) {
	ns := testutil.NewTestNamespace(t)

	rm := NewRouteManager()

	// Everything runs inside the namespace on a locked OS thread.
	err := ns.Run(func() {
		// Create two dummy interfaces to route through.
		lan := &vnl.Dummy{LinkAttrs: vnl.LinkAttrs{Name: "lan0"}}
		if err := vnl.LinkAdd(lan); err != nil {
			t.Fatalf("LinkAdd lan0: %v", err)
		}
		if err := vnl.LinkSetUp(lan); err != nil {
			t.Fatalf("LinkSetUp lan0: %v", err)
		}
		// Give lan0 an address so a gateway on its subnet is routable.
		addr, _ := vnl.ParseAddr("192.168.50.2/24")
		if err := vnl.AddrAdd(lan, addr); err != nil {
			t.Fatalf("AddrAdd lan0: %v", err)
		}

		vpn := &vnl.Dummy{LinkAttrs: vnl.LinkAttrs{Name: "wg0"}}
		if err := vnl.LinkAdd(vpn); err != nil {
			t.Fatalf("LinkAdd wg0: %v", err)
		}
		if err := vnl.LinkSetUp(vpn); err != nil {
			t.Fatalf("LinkSetUp wg0: %v", err)
		}

		// --- Case 1: gateway default route ---
		if err := rm.ReplaceDefault("lan0", "192.168.50.1", 0); err != nil {
			t.Fatalf("ReplaceDefault gateway: %v", err)
		}
		got, err := rm.GetDefaultRoute()
		if err != nil {
			t.Fatalf("GetDefaultRoute (gateway case): %v", err)
		}
		if got.Gw != "192.168.50.1" {
			t.Errorf("gateway default: Gw = %q, want 192.168.50.1", got.Gw)
		}
		if got.Iface != "lan0" {
			t.Errorf("gateway default: Iface = %q, want lan0", got.Iface)
		}
		if !got.IsDefault() {
			t.Errorf("gateway default: IsDefault() = false, want true")
		}

		// --- Case 2: device-only default route (the wg0 bug) ---
		// `default dev wg0 scope link` — no gateway. The old text parser
		// (which required "default via X") would return gw="" and drop this.
		if err := rm.ReplaceDefault("wg0", "", 0); err != nil {
			t.Fatalf("ReplaceDefault device-only: %v", err)
		}
		got, err = rm.GetDefaultRoute()
		if err != nil {
			t.Fatalf("GetDefaultRoute (device-only case): %v", err)
		}
		if got.Gw != "" {
			t.Errorf("device-only default: Gw = %q, want empty", got.Gw)
		}
		if got.Iface != "wg0" {
			t.Errorf("device-only default: Iface = %q, want wg0", got.Iface)
		}
		if !got.IsDefault() {
			t.Errorf("device-only default: IsDefault() = false, want true")
		}

		// --- Case 3: replace device-only back with a gateway route ---
		// Proves ReplaceDefault is idempotent/replacing, not additive.
		if err := rm.ReplaceDefault("lan0", "192.168.50.1", 100); err != nil {
			t.Fatalf("ReplaceDefault back to gateway w/ metric: %v", err)
		}
		got, err = rm.GetDefaultRoute()
		if err != nil {
			t.Fatalf("GetDefaultRoute (replaced case): %v", err)
		}
		if got.Gw != "192.168.50.1" || got.Iface != "lan0" {
			t.Errorf("replaced default: got Gw=%q Iface=%q, want 192.168.50.1/lan0", got.Gw, got.Iface)
		}
		if got.Metric != 100 {
			t.Errorf("replaced default: Metric = %d, want 100", got.Metric)
		}

		// ListRoutes should include the default plus the lan0 subnet route.
		routes, err := rm.ListRoutes()
		if err != nil {
			t.Fatalf("ListRoutes: %v", err)
		}
		var sawDefault bool
		for _, r := range routes {
			if r.IsDefault() {
				sawDefault = true
			}
		}
		if !sawDefault {
			t.Errorf("ListRoutes did not include a default route; got %+v", routes)
		}
	})
	if err != nil {
		t.Fatalf("namespace Run failed: %v", err)
	}
}

// TestGetDefaultRouteNoneInNamespace verifies GetDefaultRoute returns an error
// (not a panic or empty success) when there is no default route.
func TestGetDefaultRouteNoneInNamespace(t *testing.T) {
	ns := testutil.NewTestNamespace(t)
	rm := NewRouteManager()

	err := ns.Run(func() {
		if _, err := rm.GetDefaultRoute(); err == nil {
			t.Errorf("GetDefaultRoute with no default route: expected error, got nil")
		}
	})
	if err != nil {
		t.Fatalf("namespace Run failed: %v", err)
	}
}
