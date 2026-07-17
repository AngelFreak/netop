// Package firewall configures the IPv4 NAT/forwarding rules for internet
// sharing (hotspot and DHCP server) via github.com/coreos/go-iptables, replacing
// hand-built `iptables` command lines.
package firewall

import (
	"fmt"

	"github.com/coreos/go-iptables/iptables"

	"github.com/angelfreak/net/pkg/types"
)

// Compile-time assertion that the impl satisfies the interface.
var _ types.FirewallManager = (*Manager)(nil)

// Manager is the go-iptables-backed implementation of types.FirewallManager.
type Manager struct {
	ipt *iptables.IPTables
}

// New returns a FirewallManager, or an error if iptables is unavailable. The
// underlying handle uses xtables locking (-w) so concurrent iptables users
// don't clobber each other.
func New() (*Manager, error) {
	ipt, err := iptables.New()
	if err != nil {
		return nil, fmt.Errorf("initializing iptables: %w", err)
	}
	return &Manager{ipt: ipt}, nil
}

type natRule struct {
	table string
	chain string
	rule  []string
}

// natRules returns the rulespecs that implement internet sharing from
// internalIface out through outIface. Keeping them in one place guarantees
// EnableNAT and DisableNAT operate on identical rules. The MASQUERADE rule
// depends only on outIface; the two FORWARD rules depend on internalIface and
// are omitted when internalIface is empty (e.g. teardown after a crash where the
// internal interface is unknown but the MASQUERADE rule must still be removed).
func natRules(internalIface, outIface string) []natRule {
	rules := []natRule{
		{"nat", "POSTROUTING", []string{"-o", outIface, "-j", "MASQUERADE"}},
	}
	if internalIface != "" {
		rules = append(rules,
			natRule{"filter", "FORWARD", []string{"-i", internalIface, "-j", "ACCEPT"}},
			natRule{"filter", "FORWARD", []string{"-o", internalIface, "-m", "state", "--state", "RELATED,ESTABLISHED", "-j", "ACCEPT"}},
		)
	}
	return rules
}

// EnableNAT installs the NAT/forwarding rules. AppendUnique makes this
// idempotent: a rule already present is not duplicated. This is the intended
// behavior refinement over the previous delete-then-add idiom (which also
// produced exactly one rule, but by removing and re-adding on every call).
func (m *Manager) EnableNAT(internalIface, outIface string) error {
	for _, r := range natRules(internalIface, outIface) {
		if err := m.ipt.AppendUnique(r.table, r.chain, r.rule...); err != nil {
			return fmt.Errorf("adding %s/%s rule: %w", r.table, r.chain, err)
		}
	}
	return nil
}

// DisableNAT removes the NAT/forwarding rules. DeleteIfExists tolerates rules
// that were never installed (or already removed), so teardown is safe to call
// unconditionally.
func (m *Manager) DisableNAT(internalIface, outIface string) error {
	var firstErr error
	for _, r := range natRules(internalIface, outIface) {
		if err := m.ipt.DeleteIfExists(r.table, r.chain, r.rule...); err != nil && firstErr == nil {
			firstErr = fmt.Errorf("removing %s/%s rule: %w", r.table, r.chain, err)
		}
	}
	return firstErr
}
