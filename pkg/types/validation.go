package types

import (
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strings"
)

// Validation regexes - compiled once at package init
var (
	// Interface names: start with letter, alphanumeric + underscore/dash, max 15 chars
	interfaceRegex = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9_-]{0,14}$`)

	// MAC address: 6 hex pairs separated by colons
	macRegex = regexp.MustCompile(`^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$`)

	// Hostname: RFC 1123 compliant
	hostnameRegex = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$`)

	// Username: Linux username format
	usernameRegex = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,31}$`)
)

// ValidateInterfaceName validates a network interface name
func ValidateInterfaceName(name string) error {
	if name == "" {
		return fmt.Errorf("interface name cannot be empty")
	}
	if len(name) > 15 {
		return fmt.Errorf("interface name too long (max 15 characters)")
	}
	if !interfaceRegex.MatchString(name) {
		return fmt.Errorf("invalid interface name: must start with letter, contain only alphanumeric, underscore, or dash")
	}
	return nil
}

// ValidateMAC validates a MAC address format
func ValidateMAC(mac string) error {
	if mac == "" {
		return nil // Empty is allowed (means don't change)
	}
	// Special values accepted by SetMAC
	if mac == "random" || mac == "default" || mac == "permanent" {
		return nil
	}
	if !macRegex.MatchString(mac) {
		return fmt.Errorf("invalid MAC address format: expected XX:XX:XX:XX:XX:XX")
	}
	return nil
}

// ValidateSSID validates a WiFi SSID
func ValidateSSID(ssid string) error {
	if ssid == "" {
		return fmt.Errorf("SSID cannot be empty")
	}
	if len(ssid) > 32 {
		return fmt.Errorf("SSID too long (max 32 bytes)")
	}
	if strings.ContainsAny(ssid, "\x00") {
		return fmt.Errorf("SSID cannot contain null bytes")
	}
	return nil
}

// ValidatePSK validates a WiFi password/PSK.
// WPA2-PSK allows 8-63 characters. WPA3-SAE allows 8-128 characters.
// We accept up to 128 to support both modes — wpa_supplicant handles the
// mode-specific validation.
func ValidatePSK(psk string) error {
	if psk == "" {
		return nil // Open network
	}
	if len(psk) < 8 {
		return fmt.Errorf("PSK too short (minimum 8 characters)")
	}
	if len(psk) > 128 {
		return fmt.Errorf("PSK too long (maximum 128 characters)")
	}
	return nil
}

// ValidateHostname validates a hostname (RFC 1123)
func ValidateHostname(hostname string) error {
	if hostname == "" {
		return nil // Empty is allowed
	}
	// Allow template placeholders
	if strings.Contains(hostname, "<name>") {
		// Validate the parts around the template
		parts := strings.Split(hostname, "<name>")
		for _, part := range parts {
			if part != "" && !hostnameRegex.MatchString(strings.Trim(part, "-")) {
				return fmt.Errorf("invalid hostname format around template")
			}
		}
		return nil
	}
	if len(hostname) > 253 {
		return fmt.Errorf("hostname too long (max 253 characters)")
	}
	// Check each label
	labels := strings.Split(hostname, ".")
	for _, label := range labels {
		if len(label) > 63 {
			return fmt.Errorf("hostname label too long (max 63 characters)")
		}
		if !hostnameRegex.MatchString(label) {
			return fmt.Errorf("invalid hostname format: must be alphanumeric with dashes")
		}
	}
	return nil
}

// ValidateUsername validates a Linux username
func ValidateUsername(username string) error {
	if username == "" {
		return fmt.Errorf("username cannot be empty")
	}
	if !usernameRegex.MatchString(username) {
		return fmt.Errorf("invalid username format")
	}
	return nil
}

// ValidateDNSServer validates a DNS server address
func ValidateDNSServer(server string) error {
	if server == "" {
		return fmt.Errorf("DNS server cannot be empty")
	}
	if net.ParseIP(server) == nil {
		return fmt.Errorf("invalid DNS server IP address: %s", server)
	}
	return nil
}

// ValidatePortalProbeURL reports whether raw is acceptable as a captive-portal
// probe endpoint: printable ASCII only in the RAW string (the CLI prints the
// configured URL verbatim — this rules out control bytes, bidi/format runes,
// and IDN-confusable hostnames in one check), parseable, plain http (portals
// cannot intercept https), non-empty host, no userinfo. Shared by config
// load-time validation and the detector's runtime guard.
func ValidatePortalProbeURL(raw string) error {
	for _, r := range raw {
		// Visible ASCII only (0x21..0x7e): also excludes raw spaces, which
		// URL.String() can preserve in queries and which break copy/paste.
		if r < 0x21 || r > 0x7e {
			return fmt.Errorf("portal probe URL must be visible ASCII with no spaces")
		}
	}
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("invalid portal probe URL %q: %w", raw, err)
	}
	if u.Scheme != "http" {
		return fmt.Errorf("portal probe URL must be plain http, got %q — portals cannot intercept %s", raw, u.Scheme)
	}
	if u.Host == "" {
		return fmt.Errorf("portal probe URL %q has no host", raw)
	}
	if u.User != nil {
		return fmt.Errorf("portal probe URL %q must not contain userinfo", raw)
	}
	if u.Fragment != "" {
		return fmt.Errorf("portal probe URL %q must not contain a fragment — fragments are never sent over HTTP", raw)
	}
	if HasPercentEncodedControl(raw) {
		return fmt.Errorf("portal probe URL must not contain percent-encoded control bytes")
	}
	return nil
}

// HasPercentEncodedControl reports whether s contains a percent-encoded C0
// control or DEL (%00-%1F, %7F), case-insensitively. Shared by the probe-URL
// validator and pkg/portal's loginURL — downstream tooling may decode these
// even though they are inert on the terminal as-is.
func HasPercentEncodedControl(s string) bool {
	ls := strings.ToLower(s)
	for i := 0; i+2 < len(ls); i++ {
		if ls[i] != '%' {
			continue
		}
		h := ls[i+1 : i+3]
		if !isHexDigit(h[0]) || !isHexDigit(h[1]) {
			continue
		}
		if h == "7f" || h[0] == '0' || h[0] == '1' {
			return true
		}
	}
	return false
}

func isHexDigit(c byte) bool {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')
}
