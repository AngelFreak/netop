//go:build !linux

package netlink

// LinkManager is the non-Linux stub implementation of types.LinkManager.
type LinkManager struct{}

// NewLinkManager returns a stub LinkManager whose operations all fail with
// ErrUnsupported on non-Linux platforms.
func NewLinkManager() *LinkManager {
	return &LinkManager{}
}

// SetUp always returns ErrUnsupported on non-Linux platforms.
func (m *LinkManager) SetUp(iface string) error { return ErrUnsupported }

// SetDown always returns ErrUnsupported on non-Linux platforms.
func (m *LinkManager) SetDown(iface string) error { return ErrUnsupported }

// Delete always returns ErrUnsupported on non-Linux platforms.
func (m *LinkManager) Delete(iface string) error { return ErrUnsupported }

// Exists always returns ErrUnsupported on non-Linux platforms.
func (m *LinkManager) Exists(iface string) (bool, error) { return false, ErrUnsupported }

// AddWireGuard always returns ErrUnsupported on non-Linux platforms.
func (m *LinkManager) AddWireGuard(iface string) error { return ErrUnsupported }

// ListByType always returns ErrUnsupported on non-Linux platforms.
func (m *LinkManager) ListByType(linkType string) ([]string, error) { return nil, ErrUnsupported }

// GetMAC always returns ErrUnsupported on non-Linux platforms.
func (m *LinkManager) GetMAC(iface string) (string, error) { return "", ErrUnsupported }

// SetMAC always returns ErrUnsupported on non-Linux platforms.
func (m *LinkManager) SetMAC(iface, mac string) error { return ErrUnsupported }
