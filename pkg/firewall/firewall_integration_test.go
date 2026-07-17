//go:build integration && linux

package firewall

import (
	"testing"

	"github.com/angelfreak/net/tests/integration/testutil"
)

// TestFirewallManagerInNamespace exercises the real go-iptables FirewallManager
// against iptables inside an isolated network namespace: EnableNAT is idempotent
// (no duplicate rules) and DisableNAT removes the rules and tolerates missing
// ones. Failures are recorded and asserted after ns.Run returns.
//
// iptables in the namespace is independent of the host firewall, so this never
// touches the host's real rules.
func TestFirewallManagerInNamespace(t *testing.T) {
	testutil.SkipIfNotRoot(t)
	testutil.SkipIfMissingCmd(t, "iptables")
	ns := testutil.NewTestNamespace(t)

	type result struct {
		masqAfterEnable  bool
		masqAfterDouble  bool // still exactly present after a second EnableNAT (idempotent)
		masqAfterDisable bool
		err              error
	}
	var res result

	runErr := ns.Run(func() {
		fw, err := New()
		if err != nil {
			res.err = err
			return
		}
		ipt := fw.ipt

		masqExists := func() bool {
			ok, e := ipt.Exists("nat", "POSTROUTING", "-o", "eth0", "-j", "MASQUERADE")
			if e != nil {
				res.err = e
			}
			return ok
		}

		// Enable, then confirm the MASQUERADE rule exists.
		if res.err = fw.EnableNAT("wlan0", "eth0"); res.err != nil {
			return
		}
		res.masqAfterEnable = masqExists()

		// Enable again — AppendUnique must NOT create a duplicate; the rule still
		// exists exactly once (Exists returns true either way, but no error and
		// no duplicate is the point).
		if res.err = fw.EnableNAT("wlan0", "eth0"); res.err != nil {
			return
		}
		res.masqAfterDouble = masqExists()

		// Disable removes the rules; a second Disable is a tolerated no-op.
		if res.err = fw.DisableNAT("wlan0", "eth0"); res.err != nil {
			return
		}
		if res.err = fw.DisableNAT("wlan0", "eth0"); res.err != nil {
			return
		}
		res.masqAfterDisable = masqExists()
	})
	if runErr != nil {
		t.Fatalf("namespace Run failed: %v", runErr)
	}
	if res.err != nil {
		t.Fatalf("in-namespace operation failed: %v", res.err)
	}

	if !res.masqAfterEnable {
		t.Errorf("MASQUERADE rule missing after EnableNAT")
	}
	if !res.masqAfterDouble {
		t.Errorf("MASQUERADE rule missing after a second EnableNAT (idempotency broken)")
	}
	if res.masqAfterDisable {
		t.Errorf("MASQUERADE rule still present after DisableNAT")
	}
}
