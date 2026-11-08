package main

import "github.com/angelfreak/net/pkg/types"

// Payload types for the data field of the JSON envelope (see output.go).
// Field names are the contract documented by `net ai`; change them with care.

type listResult struct {
	Connections []types.Connection `json:"connections"`
}

type scanResult struct {
	Networks []types.WiFiNetwork `json:"networks"`
}

// aiResult carries the agent guide as one string so `net --json ai` stays a
// normal envelope rather than a special case.
type aiResult struct {
	Guide string `json:"guide"`
}

type genkeyResult struct {
	PrivateKey string `json:"private_key"`
	PublicKey  string `json:"public_key"`
}

// vpnEntry is a VPNStatus plus the human status label, so agents get the
// same three-way verdict (connected / ambiguous / disconnected) the text
// view shows without re-deriving it from the booleans.
type vpnEntry struct {
	types.VPNStatus
	Status string `json:"status"`
}

func vpnEntries(vpns []types.VPNStatus) []vpnEntry {
	out := make([]vpnEntry, 0, len(vpns))
	for _, v := range vpns {
		label := "disconnected"
		switch {
		case v.Connected:
			label = "connected"
		case v.Ambiguous:
			label = "ambiguous"
		}
		out = append(out, vpnEntry{VPNStatus: v, Status: label})
	}
	return out
}

type vpnListResult struct {
	VPNs []vpnEntry `json:"vpns"`
}

// Internet reachability verdicts reported by status.
const (
	internetOK          = "ok"
	internetPortal      = "portal"
	internetUnreachable = "unreachable"
	internetError       = "error"
)

type internetResult struct {
	Status       string `json:"status"`
	PortalURL    string `json:"portal_url,omitempty"`
	DefaultRoute string `json:"default_route,omitempty"`
	Error        string `json:"error,omitempty"`
}

type statusResult struct {
	Hostname   string            `json:"hostname,omitempty"`
	Interface  string            `json:"interface"`
	MAC        string            `json:"mac,omitempty"`
	MACPolicy  string            `json:"mac_policy,omitempty"`
	Connection *types.Connection `json:"connection"`
	// Internet is absent when automatic portal checks are off.
	Internet     *internetResult      `json:"internet,omitempty"`
	VPNs         []vpnEntry           `json:"vpns"`
	VPNError     string               `json:"vpn_error,omitempty"`
	Hotspot      *types.HotspotStatus `json:"hotspot"`
	HotspotError string               `json:"hotspot_error,omitempty"`
	DHCPServer   dhcpServerResult     `json:"dhcp_server"`

	// macKnown distinguishes "MAC lookup failed" (line omitted in text)
	// from an empty address; JSON just omits the field.
	macKnown bool
}

type dhcpServerResult struct {
	Running bool `json:"running"`
	// Sharing is present only while the server runs: whether clients get a
	// route to the internet, and why not if they don't.
	Sharing *types.NATState `json:"sharing,omitempty"`
}

type showCommon struct {
	DNS      []string `json:"dns"`
	MAC      string   `json:"mac,omitempty"`
	Hostname string   `json:"hostname,omitempty"`
	VPN      string   `json:"vpn,omitempty"`
}

// showNetwork is the per-network summary in `show` (all). It deliberately
// carries no secrets; `show <name>` returns a masked PSK.
type showNetwork struct {
	Interface string `json:"interface,omitempty"`
	SSID      string `json:"ssid,omitempty"`
	VPN       string `json:"vpn,omitempty"`
}

type showAllResult struct {
	Common            showCommon             `json:"common"`
	Networks          map[string]showNetwork `json:"networks"`
	VPNs              map[string]string      `json:"vpns"`
	IgnoredInterfaces []string               `json:"ignored_interfaces"`
}

func newShowAllResult(config *types.Config) showAllResult {
	r := showAllResult{
		Common: showCommon{
			DNS:      nonNil(config.Common.DNS),
			MAC:      config.Common.MAC,
			Hostname: config.Common.Hostname,
			VPN:      config.Common.VPN,
		},
		Networks:          make(map[string]showNetwork, len(config.Networks)),
		VPNs:              make(map[string]string, len(config.VPN)),
		IgnoredInterfaces: nonNil(config.Ignored.Interfaces),
	}
	for name, n := range config.Networks {
		r.Networks[name] = showNetwork{Interface: n.Interface, SSID: n.SSID, VPN: n.VPN}
	}
	for name, v := range config.VPN {
		r.VPNs[name] = v.Type
	}
	return r
}

type showNetworkResult struct {
	Name      string   `json:"name"`
	Interface string   `json:"interface,omitempty"`
	SSID      string   `json:"ssid,omitempty"`
	PSK       string   `json:"psk,omitempty"` // masked, never the real value
	DNS       []string `json:"dns"`
	MAC       string   `json:"mac,omitempty"`
	Hostname  string   `json:"hostname,omitempty"`
	VPN       string   `json:"vpn,omitempty"`
}

func newShowNetworkResult(name string, merged *types.NetworkConfig) showNetworkResult {
	r := showNetworkResult{
		Name:      name,
		Interface: merged.Interface,
		SSID:      merged.SSID,
		DNS:       nonNil(merged.DNS),
		MAC:       merged.MAC,
		Hostname:  merged.Hostname,
		VPN:       merged.VPN,
	}
	if merged.PSK != "" {
		r.PSK = maskSecret(merged.PSK)
	}
	return r
}

// nonNil returns s, or an empty slice when s is nil, so JSON shows [] not null.
func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}
