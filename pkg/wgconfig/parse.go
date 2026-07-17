// Package wgconfig applies and inspects WireGuard interface configuration via
// the kernel wireguard netlink API (wgctrl), replacing shell-outs to the `wg`
// binary. The INI parser here is platform-independent and unit-testable; the
// wgctrl-backed application lives in wg_linux.go with a stub in wg_other.go.
package wgconfig

import (
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// parseConfig parses a WireGuard INI configuration (the [Interface]/[Peer] form
// produced by wg-quick / accepted by `wg setconf`) into a wgtypes.Config that
// replaces the device's peers. It intentionally ignores wg-quick-only keys that
// belong to interface/routing setup (Address, DNS, MTU, Table, Pre/PostUp/Down)
// — those are handled elsewhere by the caller (addr/route managers) — and only
// consumes the keys the kernel device understands.
func parseConfig(config string) (wgtypes.Config, error) {
	cfg := wgtypes.Config{ReplacePeers: true}
	var peers []wgtypes.PeerConfig

	section := ""               // "interface", "peer", or ""
	var cur *wgtypes.PeerConfig // in-progress peer while section == "peer"
	curHasPublicKey := false    // whether the in-progress peer has seen a PublicKey

	flushPeer := func() error {
		if cur != nil {
			if !curHasPublicKey {
				return fmt.Errorf("[Peer] section missing PublicKey")
			}
			peers = append(peers, *cur)
			cur = nil
			curHasPublicKey = false
		}
		return nil
	}

	for lineNo, raw := range strings.Split(config, "\n") {
		line := strings.TrimSpace(raw)
		// Skip blanks and comments (';' and '#' are both used in wg configs).
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}

		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			name := strings.ToLower(strings.TrimSpace(line[1 : len(line)-1]))
			switch name {
			case "interface":
				if err := flushPeer(); err != nil {
					return wgtypes.Config{}, err
				}
				section = "interface"
			case "peer":
				if err := flushPeer(); err != nil {
					return wgtypes.Config{}, err
				}
				section = "peer"
				cur = &wgtypes.PeerConfig{ReplaceAllowedIPs: true}
			default:
				return wgtypes.Config{}, fmt.Errorf("line %d: unknown section %q", lineNo+1, line)
			}
			continue
		}

		key, value, found := strings.Cut(line, "=")
		if !found {
			return wgtypes.Config{}, fmt.Errorf("line %d: expected key = value, got %q", lineNo+1, line)
		}
		key = strings.ToLower(strings.TrimSpace(key))
		value = strings.TrimSpace(value)

		switch section {
		case "interface":
			if err := applyInterfaceKey(&cfg, key, value); err != nil {
				return wgtypes.Config{}, fmt.Errorf("line %d: %w", lineNo+1, err)
			}
		case "peer":
			if err := applyPeerKey(cur, key, value); err != nil {
				return wgtypes.Config{}, fmt.Errorf("line %d: %w", lineNo+1, err)
			}
			if key == "publickey" {
				curHasPublicKey = true
			}
		default:
			return wgtypes.Config{}, fmt.Errorf("line %d: key %q outside any section", lineNo+1, key)
		}
	}

	if err := flushPeer(); err != nil {
		return wgtypes.Config{}, err
	}
	cfg.Peers = peers
	return cfg, nil
}

// applyInterfaceKey handles keys under [Interface] that the kernel device
// understands. wg-quick-only keys (Address, DNS, MTU, Table, Pre/PostUp/Down,
// SaveConfig) are silently ignored — the caller applies those separately.
func applyInterfaceKey(cfg *wgtypes.Config, key, value string) error {
	switch key {
	case "privatekey":
		k, err := wgtypes.ParseKey(value)
		if err != nil {
			return fmt.Errorf("invalid PrivateKey: %w", err)
		}
		cfg.PrivateKey = &k
	case "listenport":
		port, err := strconv.Atoi(value)
		if err != nil || port < 0 || port > 65535 {
			return fmt.Errorf("invalid ListenPort %q", value)
		}
		cfg.ListenPort = &port
	case "fwmark":
		mark, err := strconv.Atoi(value)
		if err != nil || mark < 0 {
			return fmt.Errorf("invalid FwMark %q", value)
		}
		cfg.FirewallMark = &mark
	case "address", "dns", "mtu", "table", "preup", "postup", "predown", "postdown", "saveconfig":
		// wg-quick / routing keys handled by the caller — not device config.
	default:
		return fmt.Errorf("unknown [Interface] key %q", key)
	}
	return nil
}

// applyPeerKey handles keys under [Peer].
func applyPeerKey(peer *wgtypes.PeerConfig, key, value string) error {
	if peer == nil {
		return fmt.Errorf("key %q before any [Peer] section", key)
	}
	switch key {
	case "publickey":
		k, err := wgtypes.ParseKey(value)
		if err != nil {
			return fmt.Errorf("invalid peer PublicKey: %w", err)
		}
		peer.PublicKey = k
	case "presharedkey":
		k, err := wgtypes.ParseKey(value)
		if err != nil {
			return fmt.Errorf("invalid PresharedKey: %w", err)
		}
		peer.PresharedKey = &k
	case "endpoint":
		addr, err := resolveEndpoint(value)
		if err != nil {
			return fmt.Errorf("invalid Endpoint %q: %w", value, err)
		}
		peer.Endpoint = addr
	case "allowedips":
		nets, err := parseAllowedIPs(value)
		if err != nil {
			return err
		}
		peer.AllowedIPs = append(peer.AllowedIPs, nets...)
	case "persistentkeepalive":
		secs, err := strconv.Atoi(value)
		if err != nil || secs < 0 {
			return fmt.Errorf("invalid PersistentKeepalive %q", value)
		}
		d := time.Duration(secs) * time.Second
		peer.PersistentKeepaliveInterval = &d
	default:
		return fmt.Errorf("unknown [Peer] key %q", key)
	}
	return nil
}

// resolveEndpoint parses "host:port" (IPv4, [IPv6]:port, or hostname) into a
// net.UDPAddr, resolving hostnames via DNS.
func resolveEndpoint(endpoint string) (*net.UDPAddr, error) {
	host, portStr, err := net.SplitHostPort(endpoint)
	if err != nil {
		return nil, err
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		return nil, fmt.Errorf("invalid port %q", portStr)
	}
	// If host is a literal IP, use it directly; otherwise resolve it.
	if ip := net.ParseIP(host); ip != nil {
		return &net.UDPAddr{IP: ip, Port: port}, nil
	}
	ips, err := net.LookupIP(host)
	if err != nil || len(ips) == 0 {
		return nil, fmt.Errorf("could not resolve %q: %w", host, err)
	}
	return &net.UDPAddr{IP: ips[0], Port: port}, nil
}

// parseAllowedIPs parses a comma-separated list of CIDRs. A bare IP is treated
// as a /32 (IPv4) or /128 (IPv6).
func parseAllowedIPs(value string) ([]net.IPNet, error) {
	var nets []net.IPNet
	for _, part := range strings.Split(value, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if !strings.Contains(part, "/") {
			ip := net.ParseIP(part)
			if ip == nil {
				return nil, fmt.Errorf("invalid AllowedIP %q", part)
			}
			bits := 32
			if ip.To4() == nil {
				bits = 128
			}
			nets = append(nets, net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)})
			continue
		}
		_, ipNet, err := net.ParseCIDR(part)
		if err != nil {
			return nil, fmt.Errorf("invalid AllowedIP CIDR %q: %w", part, err)
		}
		nets = append(nets, *ipNet)
	}
	return nets, nil
}
