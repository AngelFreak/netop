//go:build linux

package netlink

import (
	"errors"
	"fmt"
	"net"

	vnl "github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"github.com/angelfreak/net/pkg/types"
)

var _ types.RuleManager = (*RuleManager)(nil)

// RuleManager is the Linux/netlink implementation of types.RuleManager.
type RuleManager struct{}

// NewRuleManager returns a netlink-backed RuleManager.
func NewRuleManager() *RuleManager {
	return &RuleManager{}
}

// AddLookupMain adds `to <dst> lookup main priority <priority>` for an IPv4
// CIDR. An identical existing rule (EEXIST) is not an error.
func (m *RuleManager) AddLookupMain(dst string, priority int) error {
	_, ipnet, err := net.ParseCIDR(dst)
	if err != nil {
		return fmt.Errorf("invalid rule destination %q: %w", dst, err)
	}
	if ipnet.IP.To4() == nil {
		return fmt.Errorf("rule destination %q is not IPv4", dst)
	}
	rule := vnl.NewRule()
	rule.Family = vnl.FAMILY_V4
	rule.Dst = ipnet
	rule.Table = unix.RT_TABLE_MAIN
	rule.Priority = priority
	if err := vnl.RuleAdd(rule); err != nil && !errors.Is(err, unix.EEXIST) {
		return fmt.Errorf("adding rule to %s lookup main priority %d: %w", dst, priority, err)
	}
	return nil
}

// DelRules removes every IPv4 rule at priority.
func (m *RuleManager) DelRules(priority int) error {
	filter := vnl.NewRule()
	filter.Priority = priority
	rules, err := vnl.RuleListFiltered(vnl.FAMILY_V4, filter, vnl.RT_FILTER_PRIORITY)
	if err != nil {
		return fmt.Errorf("listing rules at priority %d: %w", priority, err)
	}
	var errs []error
	for _, r := range rules {
		// Delete by the identifying fields only: a listed rule carries parsed
		// zero values (e.g. SuppressPrefixlen 0) that would not match.
		del := vnl.NewRule()
		del.Family = vnl.FAMILY_V4
		del.Priority = r.Priority
		del.Table = r.Table
		del.Dst = r.Dst
		del.Src = r.Src
		if err := vnl.RuleDel(del); err != nil && !errors.Is(err, unix.ENOENT) {
			errs = append(errs, fmt.Errorf("deleting rule %s: %w", r, err))
		}
	}
	return errors.Join(errs...)
}
