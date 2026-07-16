//go:build linux

package netlink

import (
	"fmt"
	"net"

	vnl "github.com/vishvananda/netlink"
)

// AddrManager is the Linux/netlink implementation of types.AddrManager.
type AddrManager struct{}

// NewAddrManager returns a netlink-backed AddrManager.
func NewAddrManager() *AddrManager {
	return &AddrManager{}
}

// GetFirstIPv4 returns the first IPv4 address assigned to iface (without the
// prefix length), or nil if the interface has no IPv4 address.
func (m *AddrManager) GetFirstIPv4(iface string) (net.IP, error) {
	link, err := vnl.LinkByName(iface)
	if err != nil {
		return nil, fmt.Errorf("resolving interface %q: %w", iface, err)
	}
	addrs, err := vnl.AddrList(link, vnl.FAMILY_V4)
	if err != nil {
		return nil, fmt.Errorf("listing addresses for %q: %w", iface, err)
	}
	for i := range addrs {
		if ip := addrs[i].IP.To4(); ip != nil {
			return ip, nil
		}
	}
	return nil, nil
}

// Add assigns the CIDR address (e.g. "10.0.0.1/24") to iface.
func (m *AddrManager) Add(iface, cidr string) error {
	link, addr, err := resolveLinkAddr(iface, cidr)
	if err != nil {
		return err
	}
	if err := vnl.AddrAdd(link, addr); err != nil {
		return fmt.Errorf("adding address %s to %q: %w", cidr, iface, err)
	}
	return nil
}

// Replace assigns the CIDR address to iface, replacing any existing address
// with the same prefix.
func (m *AddrManager) Replace(iface, cidr string) error {
	link, addr, err := resolveLinkAddr(iface, cidr)
	if err != nil {
		return err
	}
	if err := vnl.AddrReplace(link, addr); err != nil {
		return fmt.Errorf("replacing address %s on %q: %w", cidr, iface, err)
	}
	return nil
}

// Flush removes all IPv4 addresses from iface.
func (m *AddrManager) Flush(iface string) error {
	link, err := vnl.LinkByName(iface)
	if err != nil {
		return fmt.Errorf("resolving interface %q: %w", iface, err)
	}
	addrs, err := vnl.AddrList(link, vnl.FAMILY_V4)
	if err != nil {
		return fmt.Errorf("listing addresses for %q: %w", iface, err)
	}
	for i := range addrs {
		if err := vnl.AddrDel(link, &addrs[i]); err != nil {
			return fmt.Errorf("deleting address %s from %q: %w", addrs[i].IPNet, iface, err)
		}
	}
	return nil
}

// resolveLinkAddr resolves the link by name and parses the CIDR into a netlink
// Addr, validating that it is IPv4.
func resolveLinkAddr(iface, cidr string) (vnl.Link, *vnl.Addr, error) {
	link, err := vnl.LinkByName(iface)
	if err != nil {
		return nil, nil, fmt.Errorf("resolving interface %q: %w", iface, err)
	}
	addr, err := vnl.ParseAddr(cidr)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid address %q: %w", cidr, err)
	}
	if addr.IP.To4() == nil {
		return nil, nil, fmt.Errorf("address %q is not an IPv4 address", cidr)
	}
	return link, addr, nil
}
