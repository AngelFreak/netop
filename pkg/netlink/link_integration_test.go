//go:build integration && linux

package netlink

import (
	"testing"

	vnl "github.com/vishvananda/netlink"

	"github.com/angelfreak/net/tests/integration/testutil"
)

// TestLinkManagerInNamespace exercises the real netlink LinkManager against the
// kernel inside an isolated network namespace: AddWireGuard, Exists, ListByType,
// SetUp/SetDown, GetMAC/SetMAC, and Delete. Failures are recorded and asserted
// after ns.Run returns (never t.Fatal inside the closure).
func TestLinkManagerInNamespace(t *testing.T) {
	testutil.SkipIfNoWireGuard(t)
	ns := testutil.NewTestNamespace(t)
	lm := NewLinkManager()

	type result struct {
		existsAfterAdd bool
		wgList         []string
		macAfterSet    string
		existsAfterDel bool
		err            error
	}
	var res result

	runErr := ns.Run(func() {
		// AddWireGuard creates a wg interface.
		if res.err = lm.AddWireGuard("wg0"); res.err != nil {
			return
		}
		if res.existsAfterAdd, res.err = lm.Exists("wg0"); res.err != nil {
			return
		}
		if res.wgList, res.err = lm.ListByType("wireguard"); res.err != nil {
			return
		}

		// Bring it up then down (must not error).
		if res.err = lm.SetUp("wg0"); res.err != nil {
			return
		}
		if res.err = lm.SetDown("wg0"); res.err != nil {
			return
		}

		// MAC round-trip on a dummy interface (WireGuard has no L2 address).
		dummy := &vnl.Dummy{LinkAttrs: vnl.LinkAttrs{Name: "eth0"}}
		if res.err = vnl.LinkAdd(dummy); res.err != nil {
			return
		}
		if res.err = lm.SetDown("eth0"); res.err != nil {
			return
		}
		if res.err = lm.SetMAC("eth0", "02:00:00:00:00:01"); res.err != nil {
			return
		}
		if res.macAfterSet, res.err = lm.GetMAC("eth0"); res.err != nil {
			return
		}

		// Delete wg0; it should no longer exist.
		if res.err = lm.Delete("wg0"); res.err != nil {
			return
		}
		res.existsAfterDel, res.err = lm.Exists("wg0")
	})
	if runErr != nil {
		t.Fatalf("namespace Run failed: %v", runErr)
	}
	if res.err != nil {
		t.Fatalf("in-namespace operation failed: %v", res.err)
	}

	if !res.existsAfterAdd {
		t.Errorf("Exists(wg0) after AddWireGuard = false, want true")
	}
	if len(res.wgList) != 1 || res.wgList[0] != "wg0" {
		t.Errorf("ListByType(wireguard) = %v, want [wg0]", res.wgList)
	}
	if res.macAfterSet != "02:00:00:00:00:01" {
		t.Errorf("GetMAC after SetMAC = %q, want 02:00:00:00:00:01", res.macAfterSet)
	}
	if res.existsAfterDel {
		t.Errorf("Exists(wg0) after Delete = true, want false")
	}
}

// TestLinkOpsNotFoundInNamespace verifies not-found handling: Delete of a
// missing interface is a no-op (nil), and Exists returns false without error.
func TestLinkOpsNotFoundInNamespace(t *testing.T) {
	ns := testutil.NewTestNamespace(t)
	lm := NewLinkManager()

	var (
		exists    bool
		deleteErr error
		existsErr error
	)
	runErr := ns.Run(func() {
		exists, existsErr = lm.Exists("nope0")
		deleteErr = lm.Delete("nope0")
	})
	if runErr != nil {
		t.Fatalf("namespace Run failed: %v", runErr)
	}
	if existsErr != nil {
		t.Errorf("Exists(missing) returned error: %v", existsErr)
	}
	if exists {
		t.Errorf("Exists(missing) = true, want false")
	}
	if deleteErr != nil {
		t.Errorf("Delete(missing) returned error: %v, want nil (no-op)", deleteErr)
	}
}
