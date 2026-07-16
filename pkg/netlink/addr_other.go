//go:build !linux

package netlink

import (
	"net"
)

// AddrManager is the non-Linux stub implementation of types.AddrManager.
type AddrManager struct{}

// NewAddrManager returns a stub AddrManager whose operations all fail with
// ErrUnsupported on non-Linux platforms.
func NewAddrManager() *AddrManager {
	return &AddrManager{}
}

// GetFirstIPv4 always returns ErrUnsupported on non-Linux platforms.
func (m *AddrManager) GetFirstIPv4(iface string) (net.IP, error) {
	return nil, ErrUnsupported
}

// Add always returns ErrUnsupported on non-Linux platforms.
func (m *AddrManager) Add(iface, cidr string) error {
	return ErrUnsupported
}

// Replace always returns ErrUnsupported on non-Linux platforms.
func (m *AddrManager) Replace(iface, cidr string) error {
	return ErrUnsupported
}

// Flush always returns ErrUnsupported on non-Linux platforms.
func (m *AddrManager) Flush(iface string) error {
	return ErrUnsupported
}
