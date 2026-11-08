//go:build integration && linux

package netlink

import (
	"testing"

	vnl "github.com/vishvananda/netlink"

	"github.com/angelfreak/net/tests/integration/testutil"
)

// TestRuleManagerInNamespace exercises the real netlink RuleManager against the
// kernel in an isolated namespace: AddLookupMain installs `to <dst> lookup
// main` at the priority, re-adding is not an error, and DelRules removes every
// rule at that priority while leaving other priorities alone.
//
// As in TestRouteManagerInNamespace, failures are recorded inside ns.Run and
// asserted on the main goroutine; t.Fatal inside the closure would deadlock.
func TestRuleManagerInNamespace(t *testing.T) {
	ns := testutil.NewTestNamespace(t)
	rm := NewRuleManager()
	const prio, other = 5260, 5261

	type result struct {
		afterAdd, afterDel, otherKept []string
		err                           error
	}
	var res result
	atPrio := func(p int) []string {
		f := vnl.NewRule()
		f.Priority = p
		rules, err := vnl.RuleListFiltered(vnl.FAMILY_V4, f, vnl.RT_FILTER_PRIORITY)
		if err != nil {
			res.err = err
		}
		var out []string
		for _, r := range rules {
			out = append(out, r.Dst.String())
		}
		return out
	}

	runErr := ns.Run(func() {
		for _, dst := range []string{"192.168.20.0/24", "10.1.0.0/16"} {
			if res.err = rm.AddLookupMain(dst, prio); res.err != nil {
				return
			}
		}
		// Idempotent: the same rule again must not fail.
		if res.err = rm.AddLookupMain("192.168.20.0/24", prio); res.err != nil {
			return
		}
		if res.err = rm.AddLookupMain("172.16.0.0/12", other); res.err != nil {
			return
		}
		res.afterAdd = atPrio(prio)
		if res.err = rm.DelRules(prio); res.err != nil {
			return
		}
		res.afterDel = atPrio(prio)
		res.otherKept = atPrio(other)
	})
	if runErr != nil {
		t.Fatalf("namespace run: %v", runErr)
	}
	if res.err != nil {
		t.Fatalf("rule operation failed: %v", res.err)
	}
	if len(res.afterAdd) != 2 {
		t.Errorf("after adds: want 2 rules at %d (re-add must not duplicate), got %v", prio, res.afterAdd)
	}
	if len(res.afterDel) != 0 {
		t.Errorf("after DelRules: want none at %d, got %v", prio, res.afterDel)
	}
	if len(res.otherKept) != 1 || res.otherKept[0] != "172.16.0.0/12" {
		t.Errorf("DelRules(%d) must not touch priority %d, got %v", prio, other, res.otherKept)
	}
}
