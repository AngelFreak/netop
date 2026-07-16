//go:build linux

package netlink

import (
	"errors"
	"fmt"
	"net"

	vnl "github.com/vishvananda/netlink"
)

// LinkManager is the Linux/netlink implementation of types.LinkManager.
type LinkManager struct{}

// NewLinkManager returns a netlink-backed LinkManager.
func NewLinkManager() *LinkManager {
	return &LinkManager{}
}

// SetUp brings the interface administratively up.
func (m *LinkManager) SetUp(iface string) error {
	link, err := vnl.LinkByName(iface)
	if err != nil {
		return fmt.Errorf("resolving interface %q: %w", iface, err)
	}
	if err := vnl.LinkSetUp(link); err != nil {
		return fmt.Errorf("bringing up %q: %w", iface, err)
	}
	return nil
}

// SetDown brings the interface administratively down.
func (m *LinkManager) SetDown(iface string) error {
	link, err := vnl.LinkByName(iface)
	if err != nil {
		return fmt.Errorf("resolving interface %q: %w", iface, err)
	}
	if err := vnl.LinkSetDown(link); err != nil {
		return fmt.Errorf("bringing down %q: %w", iface, err)
	}
	return nil
}

// Delete removes a virtual interface (e.g. a WireGuard device).
func (m *LinkManager) Delete(iface string) error {
	link, err := vnl.LinkByName(iface)
	if err != nil {
		if isLinkNotFound(err) {
			return nil // already gone
		}
		return fmt.Errorf("resolving interface %q: %w", iface, err)
	}
	if err := vnl.LinkDel(link); err != nil {
		return fmt.Errorf("deleting %q: %w", iface, err)
	}
	return nil
}

// Exists reports whether an interface with the given name exists.
func (m *LinkManager) Exists(iface string) (bool, error) {
	_, err := vnl.LinkByName(iface)
	if err != nil {
		if isLinkNotFound(err) {
			return false, nil
		}
		return false, fmt.Errorf("resolving interface %q: %w", iface, err)
	}
	return true, nil
}

// AddWireGuard creates a WireGuard interface with the given name.
func (m *LinkManager) AddWireGuard(iface string) error {
	link := &vnl.Wireguard{LinkAttrs: vnl.LinkAttrs{Name: iface}}
	if err := vnl.LinkAdd(link); err != nil {
		return fmt.Errorf("creating WireGuard interface %q: %w", iface, err)
	}
	return nil
}

// ListByType returns the names of all interfaces of the given link type.
func (m *LinkManager) ListByType(linkType string) ([]string, error) {
	links, err := vnl.LinkList()
	if err != nil {
		return nil, fmt.Errorf("listing links: %w", err)
	}
	var names []string
	for _, link := range links {
		if link.Type() == linkType {
			names = append(names, link.Attrs().Name)
		}
	}
	return names, nil
}

// GetMAC returns the hardware (MAC) address of iface as a string.
func (m *LinkManager) GetMAC(iface string) (string, error) {
	link, err := vnl.LinkByName(iface)
	if err != nil {
		return "", fmt.Errorf("resolving interface %q: %w", iface, err)
	}
	hwAddr := link.Attrs().HardwareAddr
	if hwAddr == nil {
		return "", fmt.Errorf("interface %q has no hardware address", iface)
	}
	return hwAddr.String(), nil
}

// SetMAC sets the hardware (MAC) address of iface. The interface must be down.
func (m *LinkManager) SetMAC(iface, mac string) error {
	hwAddr, err := parseMAC(mac)
	if err != nil {
		return err
	}
	link, err := vnl.LinkByName(iface)
	if err != nil {
		return fmt.Errorf("resolving interface %q: %w", iface, err)
	}
	if err := vnl.LinkSetHardwareAddr(link, hwAddr); err != nil {
		return fmt.Errorf("setting MAC on %q: %w", iface, err)
	}
	return nil
}

// parseMAC parses and validates a MAC address string.
func parseMAC(mac string) (net.HardwareAddr, error) {
	hwAddr, err := net.ParseMAC(mac)
	if err != nil {
		return nil, fmt.Errorf("invalid MAC address %q: %w", mac, err)
	}
	return hwAddr, nil
}

// isLinkNotFound reports whether err indicates the link does not exist.
// netlink returns a LinkNotFoundError for a missing interface.
func isLinkNotFound(err error) bool {
	var notFound vnl.LinkNotFoundError
	return errors.As(err, &notFound)
}
