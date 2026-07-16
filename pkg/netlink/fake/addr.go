package fake

import (
	"net"

	"github.com/angelfreak/net/pkg/types"
)

// Compile-time assertion that the fake satisfies the interface.
var _ types.AddrManager = (*AddrManager)(nil)

// AddrManager is an in-memory fake implementation of types.AddrManager.
//
// Configure FirstIPv4 to control what GetFirstIPv4 returns. Add/Replace/Flush
// calls are recorded. Set the *Err fields to force a method to fail.
type AddrManager struct {
	// FirstIPv4 is returned by GetFirstIPv4 (as a string, parsed to net.IP).
	// Empty means "no address" (GetFirstIPv4 returns nil, nil).
	FirstIPv4 string

	// Added records every Add call in order (iface, cidr).
	Added []AddrCall
	// Replaced records every Replace call in order (iface, cidr).
	Replaced []AddrCall
	// Flushed records the interface of every Flush call in order.
	Flushed []string

	GetErr     error
	AddErr     error
	ReplaceErr error
	FlushErr   error
}

// AddrCall records the arguments of a single Add/Replace invocation.
type AddrCall struct {
	Iface string
	CIDR  string
}

// GetFirstIPv4 returns the configured FirstIPv4 parsed to a net.IP, or nil.
func (m *AddrManager) GetFirstIPv4(iface string) (net.IP, error) {
	if m.GetErr != nil {
		return nil, m.GetErr
	}
	if m.FirstIPv4 == "" {
		return nil, nil
	}
	return net.ParseIP(m.FirstIPv4), nil
}

// Add records the call.
func (m *AddrManager) Add(iface, cidr string) error {
	if m.AddErr != nil {
		return m.AddErr
	}
	m.Added = append(m.Added, AddrCall{Iface: iface, CIDR: cidr})
	return nil
}

// Replace records the call.
func (m *AddrManager) Replace(iface, cidr string) error {
	if m.ReplaceErr != nil {
		return m.ReplaceErr
	}
	m.Replaced = append(m.Replaced, AddrCall{Iface: iface, CIDR: cidr})
	return nil
}

// Flush records the call.
func (m *AddrManager) Flush(iface string) error {
	if m.FlushErr != nil {
		return m.FlushErr
	}
	m.Flushed = append(m.Flushed, iface)
	return nil
}
