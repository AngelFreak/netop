//go:build !linux

package wgconfig

import (
	"errors"

	"github.com/angelfreak/net/pkg/types"
)

// ErrUnsupported is returned by all operations on non-Linux platforms. The
// netop binary only runs on Linux; this stub exists so pkg/wgconfig (pulled in
// by pkg/vpn) cross-compiles for darwin in CI.
var ErrUnsupported = errors.New("wgconfig: WireGuard configuration is only supported on Linux")

// Configurator is the non-Linux stub implementation.
type Configurator struct{}

// New returns ErrUnsupported on non-Linux platforms.
func New() (*Configurator, error) {
	return nil, ErrUnsupported
}

// Configure returns ErrUnsupported on non-Linux platforms.
func (c *Configurator) Configure(iface, config string) error {
	return ErrUnsupported
}

// HasPeers returns ErrUnsupported on non-Linux platforms.
func (c *Configurator) HasPeers(iface string) (bool, error) {
	return false, ErrUnsupported
}

// Compile-time assertion that Configurator satisfies the interface.
var _ types.WireGuardConfigurator = (*Configurator)(nil)
