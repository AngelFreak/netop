package fake

import (
	"github.com/angelfreak/net/pkg/types"
)

// Compile-time assertion that the fake satisfies the interface.
var _ types.LinkManager = (*LinkManager)(nil)

// LinkManager is an in-memory fake implementation of types.LinkManager.
//
// Existing tracks which interfaces exist (for Exists / Delete / GetMAC).
// ByType maps a link type to interface names (for ListByType). MACs maps an
// interface to its current MAC (for GetMAC). All mutating calls are recorded.
// Set the *Err fields to force a method to fail.
type LinkManager struct {
	Existing map[string]bool
	ByType   map[string][]string
	MACs     map[string]string

	Upped       []string
	Downed      []string
	Deleted     []string
	AddedWG     []string
	SetMACCalls []MACCall

	SetUpErr   error
	SetDownErr error
	DeleteErr  error
	ExistsErr  error
	AddWGErr   error
	ListErr    error
	GetMACErr  error
	SetMACErr  error
}

// MACCall records the arguments of a single SetMAC invocation.
type MACCall struct {
	Iface string
	MAC   string
}

// SetUp records the call.
func (m *LinkManager) SetUp(iface string) error {
	if m.SetUpErr != nil {
		return m.SetUpErr
	}
	m.Upped = append(m.Upped, iface)
	return nil
}

// SetDown records the call.
func (m *LinkManager) SetDown(iface string) error {
	if m.SetDownErr != nil {
		return m.SetDownErr
	}
	m.Downed = append(m.Downed, iface)
	return nil
}

// Delete records the call and marks the interface non-existent.
func (m *LinkManager) Delete(iface string) error {
	if m.DeleteErr != nil {
		return m.DeleteErr
	}
	m.Deleted = append(m.Deleted, iface)
	if m.Existing != nil {
		delete(m.Existing, iface)
	}
	return nil
}

// Exists reports whether iface is in the Existing set.
func (m *LinkManager) Exists(iface string) (bool, error) {
	if m.ExistsErr != nil {
		return false, m.ExistsErr
	}
	return m.Existing[iface], nil
}

// AddWireGuard records the call and marks the interface existent.
func (m *LinkManager) AddWireGuard(iface string) error {
	if m.AddWGErr != nil {
		return m.AddWGErr
	}
	m.AddedWG = append(m.AddedWG, iface)
	if m.Existing == nil {
		m.Existing = map[string]bool{}
	}
	m.Existing[iface] = true
	return nil
}

// ListByType returns the configured interface names for the given type.
func (m *LinkManager) ListByType(linkType string) ([]string, error) {
	if m.ListErr != nil {
		return nil, m.ListErr
	}
	return m.ByType[linkType], nil
}

// GetMAC returns the configured MAC for iface.
func (m *LinkManager) GetMAC(iface string) (string, error) {
	if m.GetMACErr != nil {
		return "", m.GetMACErr
	}
	return m.MACs[iface], nil
}

// SetMAC records the call and updates the in-memory MAC.
func (m *LinkManager) SetMAC(iface, mac string) error {
	if m.SetMACErr != nil {
		return m.SetMACErr
	}
	m.SetMACCalls = append(m.SetMACCalls, MACCall{Iface: iface, MAC: mac})
	if m.MACs == nil {
		m.MACs = map[string]string{}
	}
	m.MACs[iface] = mac
	return nil
}
