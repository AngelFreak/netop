// Package fake provides an in-memory test double for types.FirewallManager.
package fake

import (
	"github.com/angelfreak/net/pkg/types"
)

// Compile-time assertion that the fake satisfies the interface.
var _ types.FirewallManager = (*Manager)(nil)

// Manager is an in-memory fake implementation of types.FirewallManager. It
// records EnableNAT/DisableNAT calls and tracks which (internal,out) pairs are
// currently enabled. Set the *Err fields to force a method to fail.
type Manager struct {
	// Enabled records every EnableNAT call in order.
	Enabled []NATCall
	// Disabled records every DisableNAT call in order.
	Disabled []NATCall

	EnableErr  error
	DisableErr error
}

// NATCall records the arguments of a single EnableNAT/DisableNAT invocation.
type NATCall struct {
	Internal string
	Out      string
}

// EnableNAT records the call.
func (m *Manager) EnableNAT(internalIface, outIface string) error {
	if m.EnableErr != nil {
		return m.EnableErr
	}
	m.Enabled = append(m.Enabled, NATCall{Internal: internalIface, Out: outIface})
	return nil
}

// DisableNAT records the call.
func (m *Manager) DisableNAT(internalIface, outIface string) error {
	if m.DisableErr != nil {
		return m.DisableErr
	}
	m.Disabled = append(m.Disabled, NATCall{Internal: internalIface, Out: outIface})
	return nil
}
