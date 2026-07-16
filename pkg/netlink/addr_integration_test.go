//go:build integration && linux

package netlink

import (
	"testing"

	vnl "github.com/vishvananda/netlink"

	"github.com/angelfreak/net/tests/integration/testutil"
)

// TestAddrManagerInNamespace exercises the real netlink AddrManager against the
// kernel inside an isolated network namespace: Add, GetFirstIPv4, Replace, and
// Flush all round-trip. Failures are recorded and asserted after ns.Run returns
// (never t.Fatal inside the closure — see route_integration_test.go).
func TestAddrManagerInNamespace(t *testing.T) {
	ns := testutil.NewTestNamespace(t)
	am := NewAddrManager()

	type result struct {
		afterAdd     string
		afterReplace string
		afterFlush   string // "" expected (no address)
		flushedNil   bool
		err          error
	}
	var res result

	runErr := ns.Run(func() {
		link := &vnl.Dummy{LinkAttrs: vnl.LinkAttrs{Name: "eth0"}}
		if res.err = vnl.LinkAdd(link); res.err != nil {
			return
		}
		if res.err = vnl.LinkSetUp(link); res.err != nil {
			return
		}

		// Add an address, then read it back.
		if res.err = am.Add("eth0", "10.0.0.5/24"); res.err != nil {
			return
		}
		ip, err := am.GetFirstIPv4("eth0")
		if err != nil {
			res.err = err
			return
		}
		if ip != nil {
			res.afterAdd = ip.String()
		}

		// Replace the same address — must be idempotent (no error, still present).
		if res.err = am.Replace("eth0", "10.0.0.5/24"); res.err != nil {
			return
		}
		ip, err = am.GetFirstIPv4("eth0")
		if err != nil {
			res.err = err
			return
		}
		if ip != nil {
			res.afterReplace = ip.String()
		}

		// Flush removes all addresses; GetFirstIPv4 then returns nil, nil.
		if res.err = am.Flush("eth0"); res.err != nil {
			return
		}
		ip, err = am.GetFirstIPv4("eth0")
		if err != nil {
			res.err = err
			return
		}
		res.flushedNil = ip == nil
	})
	if runErr != nil {
		t.Fatalf("namespace Run failed: %v", runErr)
	}
	if res.err != nil {
		t.Fatalf("in-namespace operation failed: %v", res.err)
	}

	if res.afterAdd != "10.0.0.5" {
		t.Errorf("after Add: GetFirstIPv4 = %q, want 10.0.0.5", res.afterAdd)
	}
	// Replace of the same address is idempotent — the address is still present.
	if res.afterReplace != "10.0.0.5" {
		t.Errorf("after idempotent Replace: GetFirstIPv4 = %q, want 10.0.0.5", res.afterReplace)
	}
	if !res.flushedNil {
		t.Errorf("after Flush: GetFirstIPv4 should return nil, got %q", res.afterFlush)
	}
}

// TestGetFirstIPv4NoAddressInNamespace verifies GetFirstIPv4 returns (nil, nil)
// for an interface with no IPv4 address (not an error).
func TestGetFirstIPv4NoAddressInNamespace(t *testing.T) {
	ns := testutil.NewTestNamespace(t)
	am := NewAddrManager()

	var (
		gotNil bool
		gotErr error
	)
	runErr := ns.Run(func() {
		link := &vnl.Dummy{LinkAttrs: vnl.LinkAttrs{Name: "eth9"}}
		if err := vnl.LinkAdd(link); err != nil {
			gotErr = err
			return
		}
		ip, err := am.GetFirstIPv4("eth9")
		if err != nil {
			gotErr = err
			return
		}
		gotNil = ip == nil
	})
	if runErr != nil {
		t.Fatalf("namespace Run failed: %v", runErr)
	}
	if gotErr != nil {
		t.Fatalf("in-namespace operation failed: %v", gotErr)
	}
	if !gotNil {
		t.Errorf("GetFirstIPv4 on address-less interface: expected nil, got an address")
	}
}
