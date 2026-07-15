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
//
// IMPORTANT: the function passed to ns.Run executes in a separate, OS-thread-
// locked goroutine. Calling t.Fatal*/t.FailNow there would runtime.Goexit that
// goroutine, so ns.Run's completion send never fires and the test deadlocks.
// This test therefore records failures into a result struct and asserts on the
// main goroutine after Run returns — never t.Fatal inside the closure.
func TestRouteManagerInNamespace(t *testing.T) {
	ns := testutil.NewTestNamespace(t)
	rm := NewRouteManager()

	type result struct {
		gwRoute  *routeSnapshot
		devRoute *routeSnapshot
		replaced *routeSnapshot
		sawList  bool
		err      error
	}
	var res result

	runErr := ns.Run(func() {
		// Create two dummy interfaces to route through.
		lan := &vnl.Dummy{LinkAttrs: vnl.LinkAttrs{Name: "lan0"}}
		if res.err = vnl.LinkAdd(lan); res.err != nil {
			return
		}
		if res.err = vnl.LinkSetUp(lan); res.err != nil {
			return
		}
		// Give lan0 an address so a gateway on its subnet is routable.
		addr, _ := vnl.ParseAddr("192.168.50.2/24")
		if res.err = vnl.AddrAdd(lan, addr); res.err != nil {
			return
		}

		vpn := &vnl.Dummy{LinkAttrs: vnl.LinkAttrs{Name: "wg0"}}
		if res.err = vnl.LinkAdd(vpn); res.err != nil {
			return
		}
		if res.err = vnl.LinkSetUp(vpn); res.err != nil {
			return
		}

		// --- Case 1: gateway default route ---
		if res.err = rm.ReplaceDefault("lan0", "192.168.50.1", 0); res.err != nil {
			return
		}
		if res.gwRoute, res.err = snapshotDefault(rm); res.err != nil {
			return
		}

		// --- Case 2: device-only default route (the wg0 bug) ---
		// `default dev wg0 scope link` — no gateway.
		if res.err = rm.ReplaceDefault("wg0", "", 0); res.err != nil {
			return
		}
		if res.devRoute, res.err = snapshotDefault(rm); res.err != nil {
			return
		}

		// --- Case 3: replace device-only back with a gateway route + metric ---
		if res.err = rm.ReplaceDefault("lan0", "192.168.50.1", 100); res.err != nil {
			return
		}
		if res.replaced, res.err = snapshotDefault(rm); res.err != nil {
			return
		}

		// ListRoutes should include the default route.
		routes, err := rm.ListRoutes()
		if err != nil {
			res.err = err
			return
		}
		for _, r := range routes {
			if r.IsDefault() {
				res.sawList = true
			}
		}
	})
	if runErr != nil {
		t.Fatalf("namespace Run failed: %v", runErr)
	}
	if res.err != nil {
		t.Fatalf("in-namespace operation failed: %v", res.err)
	}

	// Case 1: gateway default route.
	if res.gwRoute.gw != "192.168.50.1" {
		t.Errorf("gateway default: Gw = %q, want 192.168.50.1", res.gwRoute.gw)
	}
	if res.gwRoute.iface != "lan0" {
		t.Errorf("gateway default: Iface = %q, want lan0", res.gwRoute.iface)
	}
	if !res.gwRoute.isDefault {
		t.Errorf("gateway default: IsDefault() = false, want true")
	}

	// Case 2: device-only default route — the motivating bug.
	if res.devRoute.gw != "" {
		t.Errorf("device-only default: Gw = %q, want empty", res.devRoute.gw)
	}
	if res.devRoute.iface != "wg0" {
		t.Errorf("device-only default: Iface = %q, want wg0", res.devRoute.iface)
	}
	if !res.devRoute.isDefault {
		t.Errorf("device-only default: IsDefault() = false, want true")
	}

	// Case 3: replaced back to a gateway route with metric 100.
	if res.replaced.gw != "192.168.50.1" || res.replaced.iface != "lan0" {
		t.Errorf("replaced default: got Gw=%q Iface=%q, want 192.168.50.1/lan0", res.replaced.gw, res.replaced.iface)
	}
	if res.replaced.metric != 100 {
		t.Errorf("replaced default: Metric = %d, want 100", res.replaced.metric)
	}

	if !res.sawList {
		t.Errorf("ListRoutes did not include a default route")
	}
}

// TestGetDefaultRouteNoneInNamespace verifies GetDefaultRoute returns an error
// (not a panic or empty success) when there is no default route.
func TestGetDefaultRouteNoneInNamespace(t *testing.T) {
	ns := testutil.NewTestNamespace(t)
	rm := NewRouteManager()

	var gotErr bool
	runErr := ns.Run(func() {
		if _, err := rm.GetDefaultRoute(); err != nil {
			gotErr = true
		}
	})
	if runErr != nil {
		t.Fatalf("namespace Run failed: %v", runErr)
	}
	if !gotErr {
		t.Errorf("GetDefaultRoute with no default route: expected error, got nil")
	}
}

// routeSnapshot captures the fields of a default route for assertion outside
// the namespace goroutine.
type routeSnapshot struct {
	gw        string
	iface     string
	metric    int
	isDefault bool
}

func snapshotDefault(rm *RouteManager) (*routeSnapshot, error) {
	r, err := rm.GetDefaultRoute()
	if err != nil {
		return nil, err
	}
	return &routeSnapshot{
		gw:        r.Gw,
		iface:     r.Iface,
		metric:    r.Metric,
		isDefault: r.IsDefault(),
	}, nil
}
