package types

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestValidateInterfaceName(t *testing.T) {
	tests := []struct {
		name    string
		iface   string
		wantErr bool
	}{
		{"valid eth0", "eth0", false},
		{"valid wlan0", "wlan0", false},
		{"valid enp0s3", "enp0s3", false},
		{"valid with underscore", "eth_0", false},
		{"valid with dash", "eth-0", false},
		{"valid max length", "abcdefghijklmno", false},
		{"empty", "", true},
		{"too long", "abcdefghijklmnop", true},
		{"starts with number", "0eth", true},
		{"contains space", "eth 0", true},
		{"contains slash", "eth/0", true},
		{"contains semicolon", "eth;rm -rf", true},
		{"path traversal attempt", "../../../etc", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateInterfaceName(tt.iface)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidateMAC(t *testing.T) {
	tests := []struct {
		name    string
		mac     string
		wantErr bool
	}{
		{"valid lowercase", "aa:bb:cc:dd:ee:ff", false},
		{"valid uppercase", "AA:BB:CC:DD:EE:FF", false},
		{"valid mixed", "Aa:Bb:Cc:Dd:Ee:Ff", false},
		{"empty", "", false},
		{"random keyword", "random", false},
		{"permanent keyword", "permanent", false},
		{"too short", "aa:bb:cc:dd:ee", true},
		{"too long", "aa:bb:cc:dd:ee:ff:00", true},
		{"wrong separator", "aa-bb-cc-dd-ee-ff", true},
		{"invalid hex", "gg:bb:cc:dd:ee:ff", true},
		{"no separator", "aabbccddeeff", true},
		{"injection attempt", "aa:bb:cc:dd:ee:ff;rm", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateMAC(tt.mac)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidateSSID(t *testing.T) {
	tests := []struct {
		name    string
		ssid    string
		wantErr bool
	}{
		{"valid simple", "MyNetwork", false},
		{"valid with spaces", "My Network", false},
		{"valid with special chars", "My-Network_123!", false},
		{"valid max length", "12345678901234567890123456789012", false},
		{"empty", "", true},
		{"too long", "123456789012345678901234567890123", true},
		{"contains null", "My\x00Network", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateSSID(tt.ssid)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidatePSK(t *testing.T) {
	tests := []struct {
		name    string
		psk     string
		wantErr bool
	}{
		{"valid 8 chars", "password", false},
		{"valid 63 chars", "123456789012345678901234567890123456789012345678901234567890123", false},
		{"empty (open network)", "", false},
		{"too short", "pass", true},
		{"too long 64 chars", "1234567890123456789012345678901234567890123456789012345678901234", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidatePSK(tt.psk)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidateHostname(t *testing.T) {
	tests := []struct {
		name     string
		hostname string
		wantErr  bool
	}{
		{"valid simple", "myhost", false},
		{"valid with dash", "my-host", false},
		{"valid with numbers", "host123", false},
		{"valid fqdn", "host.example.com", false},
		{"valid template", "prefix-<name>-suffix", false},
		{"empty", "", false},
		{"starts with dash", "-myhost", true},
		{"ends with dash", "myhost-", true},
		{"contains underscore", "my_host", true},
		{"contains space", "my host", true},
		{"label too long", "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijkl", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateHostname(tt.hostname)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidateUsername(t *testing.T) {
	tests := []struct {
		name     string
		username string
		wantErr  bool
	}{
		{"valid simple", "user", false},
		{"valid with underscore", "user_name", false},
		{"valid with dash", "user-name", false},
		{"valid with numbers", "user123", false},
		{"valid starts with underscore", "_user", false},
		{"empty", "", true},
		{"starts with dash", "-user", true},
		{"starts with number", "1user", true},
		{"contains space", "user name", true},
		{"path traversal", "../../../", true},
		{"too long", "abcdefghijklmnopqrstuvwxyz123456789", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateUsername(tt.username)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidateDNSServer(t *testing.T) {
	tests := []struct {
		name    string
		server  string
		wantErr bool
	}{
		// Valid IPv4 addresses
		{"valid ipv4 google", "8.8.8.8", false},
		{"valid ipv4 cloudflare", "1.1.1.1", false},
		{"valid ipv4 local", "192.168.1.1", false},
		{"valid ipv4 zeros", "0.0.0.0", false},
		{"valid ipv4 max", "255.255.255.255", false},

		// Valid IPv6 addresses
		{"valid ipv6 google", "2001:4860:4860::8888", false},
		{"valid ipv6 cloudflare", "2606:4700:4700::1111", false},
		{"valid ipv6 loopback", "::1", false},
		{"valid ipv6 full", "2001:0db8:85a3:0000:0000:8a2e:0370:7334", false},

		// Invalid cases
		{"empty", "", true},
		{"invalid ipv4 octet too high", "256.1.1.1", true},
		{"invalid ipv4 too few octets", "192.168.1", true},
		{"invalid ipv4 too many octets", "192.168.1.1.1", true},
		{"invalid ipv4 letters", "abc.def.ghi.jkl", true},
		{"invalid ipv4 trailing dot", "192.168.1.1.", true},
		{"invalid ipv4 leading dot", ".192.168.1.1", true},
		{"invalid ipv4 negative", "-1.0.0.0", true},
		{"invalid ipv6 invalid char", "2001:xyz::1", true},
		{"invalid hostname", "dns.google.com", true},
		{"invalid random string", "not-an-ip", true},
		{"invalid with port", "8.8.8.8:53", true},
		{"invalid whitespace", " 8.8.8.8", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateDNSServer(tt.server)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestParseIP(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		wantNil  bool
	}{
		// IPv4 cases
		{"valid ipv4", "192.168.1.1", false},
		{"valid ipv4 zeros", "0.0.0.0", false},

		// IPv6 cases
		{"valid ipv6 short", "::1", false},
		{"valid ipv6 full", "2001:db8::1", false},

		// Invalid cases
		{"empty string", "", true},
		{"no separator", "12345678", true},
		{"letters only", "abcdefgh", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parseIP(tt.input)
			if tt.wantNil {
				assert.Nil(t, result)
			} else {
				assert.NotNil(t, result)
			}
		})
	}
}

func TestParseIPv4(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantNil bool
		want    []byte
	}{
		// Valid cases
		{"valid basic", "192.168.1.1", false, []byte{192, 168, 1, 1}},
		{"valid zeros", "0.0.0.0", false, []byte{0, 0, 0, 0}},
		{"valid max", "255.255.255.255", false, []byte{255, 255, 255, 255}},
		{"valid loopback", "127.0.0.1", false, []byte{127, 0, 0, 1}},

		// Invalid cases
		{"empty string", "", true, nil},
		{"too few octets", "192.168.1", true, nil},
		{"too many octets", "192.168.1.1.1", true, nil},
		{"octet too high", "256.0.0.0", true, nil},
		{"negative octet", "-1.0.0.0", true, nil},
		{"missing first octet", ".168.1.1", true, nil},
		{"missing middle octet", "192..1.1", true, nil},
		{"trailing dot", "192.168.1.1.", true, nil},
		{"leading zeros large", "192.168.1.256", true, nil},
		{"letters in octet", "192.168.a.1", true, nil},
		{"double dot", "192..168.1", true, nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parseIPv4(tt.input)
			if tt.wantNil {
				assert.Nil(t, result)
			} else {
				assert.Equal(t, tt.want, result)
			}
		})
	}
}

func TestParseIPv6(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantNil bool
	}{
		// Valid cases (returns placeholder, just validates format)
		{"valid loopback", "::1", false},
		{"valid full", "2001:0db8:85a3:0000:0000:8a2e:0370:7334", false},
		{"valid compressed", "2001:db8::1", false},
		{"valid google dns", "2001:4860:4860::8888", false},
		{"valid all zeros", "::", false},
		{"valid hex chars", "abcd:ef01:2345:6789:abcd:ef01:2345:6789", false},
		{"valid uppercase hex", "ABCD:EF01:2345:6789:ABCD:EF01:2345:6789", false},

		// Invalid cases
		{"too short", ":", true},
		{"empty", "", true},
		{"contains invalid char g", "200g:db8::1", true},
		{"contains invalid char z", "2001:dbz::1", true},
		{"contains dot", "2001:db8.::1", true},
		{"contains space", "2001: db8::1", true},
		{"contains slash", "2001/db8::1", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parseIPv6(tt.input)
			if tt.wantNil {
				assert.Nil(t, result)
			} else {
				assert.NotNil(t, result)
			}
		})
	}
}

func TestDtoi(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		wantN  int
		wantI  int
		wantOK bool
	}{
		// Valid cases
		{"single digit zero", "0", 0, 1, true},
		{"single digit", "5", 5, 1, true},
		{"double digit", "42", 42, 2, true},
		{"triple digit", "123", 123, 3, true},
		{"max byte value", "255", 255, 3, true},
		{"larger number", "1000", 1000, 4, true},

		// Partial parsing (stops at non-digit)
		{"number then letter", "123abc", 123, 3, true},
		{"number then dot", "192.168", 192, 3, true},
		{"number then colon", "80:443", 80, 2, true},

		// Invalid cases
		{"empty string", "", 0, 0, false},
		{"starts with letter", "abc", 0, 0, false},
		{"starts with dot", ".123", 0, 0, false},
		{"starts with minus", "-5", 0, 0, false},

		// Overflow protection
		{"overflow large number", "16777216", 0, 7, false}, // 0xFFFFFF + 1 = 16777216
		{"near overflow", "16777214", 16777214, 8, true},   // Just under 0xFFFFFF
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			n, i, ok := dtoi(tt.input)
			assert.Equal(t, tt.wantOK, ok, "ok mismatch")
			if tt.wantOK {
				assert.Equal(t, tt.wantN, n, "n mismatch")
				assert.Equal(t, tt.wantI, i, "i mismatch")
			}
		})
	}
}

func TestTimeoutConfigGetDHCPTimeout(t *testing.T) {
	tests := []struct {
		name     string
		config   TimeoutConfig
		expected time.Duration
	}{
		{"default when zero", TimeoutConfig{DHCP: 0}, 30 * time.Second},
		{"default when negative", TimeoutConfig{DHCP: -1}, 30 * time.Second},
		{"custom 10 seconds", TimeoutConfig{DHCP: 10}, 10 * time.Second},
		{"custom 60 seconds", TimeoutConfig{DHCP: 60}, 60 * time.Second},
		{"custom 1 second", TimeoutConfig{DHCP: 1}, 1 * time.Second},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.config.GetDHCPTimeout()
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestTimeoutConfigGetAssociationTimeout(t *testing.T) {
	tests := []struct {
		name     string
		config   TimeoutConfig
		expected time.Duration
	}{
		{"default when zero", TimeoutConfig{Association: 0}, 30 * time.Second},
		{"default when negative", TimeoutConfig{Association: -1}, 30 * time.Second},
		{"custom 15 seconds", TimeoutConfig{Association: 15}, 15 * time.Second},
		{"custom 120 seconds", TimeoutConfig{Association: 120}, 120 * time.Second},
		{"custom 1 second", TimeoutConfig{Association: 1}, 1 * time.Second},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.config.GetAssociationTimeout()
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestTimeoutConfigGetCommandTimeout(t *testing.T) {
	tests := []struct {
		name     string
		config   TimeoutConfig
		expected time.Duration
	}{
		{"default when zero", TimeoutConfig{Command: 0}, 30 * time.Second},
		{"default when negative", TimeoutConfig{Command: -1}, 30 * time.Second},
		{"custom 5 seconds", TimeoutConfig{Command: 5}, 5 * time.Second},
		{"custom 300 seconds", TimeoutConfig{Command: 300}, 300 * time.Second},
		{"custom 1 second", TimeoutConfig{Command: 1}, 1 * time.Second},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.config.GetCommandTimeout()
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestTimeoutConfigGetCarrierTimeout(t *testing.T) {
	tests := []struct {
		name     string
		config   TimeoutConfig
		expected time.Duration
	}{
		{"default when zero", TimeoutConfig{Carrier: 0}, 5 * time.Second},
		{"default when negative", TimeoutConfig{Carrier: -1}, 5 * time.Second},
		{"custom 10 seconds", TimeoutConfig{Carrier: 10}, 10 * time.Second},
		{"custom 30 seconds", TimeoutConfig{Carrier: 30}, 30 * time.Second},
		{"custom 1 second", TimeoutConfig{Carrier: 1}, 1 * time.Second},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.config.GetCarrierTimeout()
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestTimeoutConfigAllDefaults(t *testing.T) {
	// Test that a zero-value TimeoutConfig returns all defaults
	config := TimeoutConfig{}

	assert.Equal(t, 30*time.Second, config.GetDHCPTimeout())
	assert.Equal(t, 30*time.Second, config.GetAssociationTimeout())
	assert.Equal(t, 30*time.Second, config.GetCommandTimeout())
	assert.Equal(t, 5*time.Second, config.GetCarrierTimeout())
}

func TestTimeoutConfigAllCustom(t *testing.T) {
	// Test that all custom values are respected
	config := TimeoutConfig{
		DHCP:        45,
		Association: 60,
		Command:     120,
		Carrier:     15,
	}

	assert.Equal(t, 45*time.Second, config.GetDHCPTimeout())
	assert.Equal(t, 60*time.Second, config.GetAssociationTimeout())
	assert.Equal(t, 120*time.Second, config.GetCommandTimeout())
	assert.Equal(t, 15*time.Second, config.GetCarrierTimeout())
}
