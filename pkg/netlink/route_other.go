//go:build !linux

// This file is the non-Linux stub for the netlink package. netop is a Linux
// network manager, but CI cross-compiles darwin binaries; on those platforms
// every RouteManager operation returns ErrUnsupported instead of failing to
// build (github.com/vishvananda/netlink is Linux-only).
package netlink

import (
	"errors"

	"github.com/angelfreak/net/pkg/types"
)

// ErrUnsupported is returned by all RouteManager operations on non-Linux
// platforms, where rtnetlink is unavailable.
var ErrUnsupported = errors.New("netlink route operations are only supported on Linux")

// Compile-time assertions that the stub implementations satisfy the typed
// manager interfaces.
var (
	_ types.RouteManager = (*RouteManager)(nil)
	_ types.AddrManager  = (*AddrManager)(nil)
	_ types.LinkManager  = (*LinkManager)(nil)
)

// RouteManager is the non-Linux stub implementation of types.RouteManager.
type RouteManager struct{}

// NewRouteManager returns a stub RouteManager whose operations all fail with
// ErrUnsupported on non-Linux platforms.
func NewRouteManager() *RouteManager {
	return &RouteManager{}
}

// GetDefaultRoute always returns ErrUnsupported on non-Linux platforms.
func (m *RouteManager) GetDefaultRoute() (*types.Route, error) {
	return nil, ErrUnsupported
}

// GetDefaultRouteForIface always returns ErrUnsupported on non-Linux platforms.
func (m *RouteManager) GetDefaultRouteForIface(iface string) (*types.Route, error) {
	return nil, ErrUnsupported
}

// ReplaceDefault always returns ErrUnsupported on non-Linux platforms.
func (m *RouteManager) ReplaceDefault(iface, gw string, metric int) error {
	return ErrUnsupported
}

// SetDefaultForIface always returns ErrUnsupported on non-Linux platforms.
func (m *RouteManager) SetDefaultForIface(iface, gw string, metric int) error {
	return ErrUnsupported
}

// AddRoute always returns ErrUnsupported on non-Linux platforms.
func (m *RouteManager) AddRoute(iface, destination, gw string) error {
	return ErrUnsupported
}

// ReplaceRoute always returns ErrUnsupported on non-Linux platforms.
func (m *RouteManager) ReplaceRoute(iface, destination, gw string) error {
	return ErrUnsupported
}

// DelRoute always returns ErrUnsupported on non-Linux platforms.
func (m *RouteManager) DelRoute(destination string) error {
	return ErrUnsupported
}

// FlushRoutes always returns ErrUnsupported on non-Linux platforms.
func (m *RouteManager) FlushRoutes(iface string) error {
	return ErrUnsupported
}

// ListRoutes always returns ErrUnsupported on non-Linux platforms.
func (m *RouteManager) ListRoutes() ([]types.Route, error) {
	return nil, ErrUnsupported
}
