//go:build linux

package wgconfig

import (
	"fmt"

	"github.com/angelfreak/net/pkg/types"
	"golang.zx2c4.com/wireguard/wgctrl"
)

// Configurator is the wgctrl-backed implementation of
// types.WireGuardConfigurator. A fresh wgctrl client is opened per call and
// closed immediately — the operations are infrequent (connect/status) and this
// avoids holding a netlink socket open for the manager's lifetime.
type Configurator struct{}

// New returns a WireGuard configurator backed by the kernel wireguard netlink
// API. It fails fast if a wgctrl client cannot be opened (e.g. the wireguard
// module is unavailable), matching the fail-fast behavior of the other managers.
func New() (*Configurator, error) {
	client, err := wgctrl.New()
	if err != nil {
		return nil, fmt.Errorf("opening wgctrl client: %w", err)
	}
	_ = client.Close()
	return &Configurator{}, nil
}

// Configure parses the INI config and applies it to iface via
// wgctrl.ConfigureDevice, replacing the device's peers (equivalent to
// `wg setconf`).
func (c *Configurator) Configure(iface, config string) error {
	cfg, err := parseConfig(config)
	if err != nil {
		return fmt.Errorf("parsing WireGuard config: %w", err)
	}
	client, err := wgctrl.New()
	if err != nil {
		return fmt.Errorf("opening wgctrl client: %w", err)
	}
	defer client.Close()
	if err := client.ConfigureDevice(iface, cfg); err != nil {
		return fmt.Errorf("configuring %s: %w", iface, err)
	}
	return nil
}

// HasPeers reports whether iface has at least one configured peer.
func (c *Configurator) HasPeers(iface string) (bool, error) {
	client, err := wgctrl.New()
	if err != nil {
		return false, fmt.Errorf("opening wgctrl client: %w", err)
	}
	defer client.Close()
	device, err := client.Device(iface)
	if err != nil {
		return false, fmt.Errorf("reading device %s: %w", iface, err)
	}
	return len(device.Peers) > 0, nil
}

// Compile-time assertion that Configurator satisfies the interface.
var _ types.WireGuardConfigurator = (*Configurator)(nil)
