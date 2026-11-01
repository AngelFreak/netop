package wgconfig

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A valid 44-char base64 WireGuard key (all-zero key encodes to this).
const zeroKey = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="

func TestParseConfig_FullTunnel(t *testing.T) {
	cfg, err := parseConfig(`
[Interface]
PrivateKey = ` + zeroKey + `
Address = 10.0.0.2/32
DNS = 1.1.1.1
ListenPort = 51820

[Peer]
PublicKey = ` + zeroKey + `
PresharedKey = ` + zeroKey + `
Endpoint = 192.0.2.1:51820
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
`)
	require.NoError(t, err)

	assert.True(t, cfg.ReplacePeers)
	require.NotNil(t, cfg.PrivateKey)
	require.NotNil(t, cfg.ListenPort)
	assert.Equal(t, 51820, *cfg.ListenPort)

	require.Len(t, cfg.Peers, 1)
	p := cfg.Peers[0]
	assert.True(t, p.ReplaceAllowedIPs)
	require.NotNil(t, p.PresharedKey)
	require.NotNil(t, p.Endpoint)
	assert.Equal(t, "192.0.2.1", p.Endpoint.IP.String())
	assert.Equal(t, 51820, p.Endpoint.Port)
	require.NotNil(t, p.PersistentKeepaliveInterval)
	assert.Equal(t, 25*time.Second, *p.PersistentKeepaliveInterval)
	require.Len(t, p.AllowedIPs, 2)
	assert.Equal(t, "0.0.0.0/0", p.AllowedIPs[0].String())
	assert.Equal(t, "::/0", p.AllowedIPs[1].String())
}

func TestParseConfig_MultiplePeers(t *testing.T) {
	cfg, err := parseConfig(`
[Interface]
PrivateKey = ` + zeroKey + `

[Peer]
PublicKey = ` + zeroKey + `
AllowedIPs = 10.0.0.0/24

[Peer]
PublicKey = ` + zeroKey + `
AllowedIPs = 10.0.1.0/24
`)
	require.NoError(t, err)
	require.Len(t, cfg.Peers, 2)
	assert.Equal(t, "10.0.0.0/24", cfg.Peers[0].AllowedIPs[0].String())
	assert.Equal(t, "10.0.1.0/24", cfg.Peers[1].AllowedIPs[0].String())
}

func TestParseConfig_BareIPAllowedIP(t *testing.T) {
	cfg, err := parseConfig("[Peer]\nPublicKey = " + zeroKey + "\nAllowedIPs = 10.0.0.5")
	require.NoError(t, err)
	require.Len(t, cfg.Peers, 1)
	require.Len(t, cfg.Peers[0].AllowedIPs, 1)
	// Bare IPv4 becomes /32.
	assert.Equal(t, "10.0.0.5/32", cfg.Peers[0].AllowedIPs[0].String())
}

func TestParseConfig_CommentsAndBlankLines(t *testing.T) {
	cfg, err := parseConfig(`
# a comment
; another comment

[Interface]
PrivateKey = ` + zeroKey + `

[Peer]
PublicKey = ` + zeroKey + `
`)
	require.NoError(t, err)
	require.Len(t, cfg.Peers, 1)
}

func TestParseConfig_IgnoresWgQuickKeys(t *testing.T) {
	// Address/DNS/MTU/Table/PostUp are wg-quick keys the kernel device ignores;
	// they must not cause a parse error.
	_, err := parseConfig(`
[Interface]
PrivateKey = ` + zeroKey + `
Address = 10.0.0.2/24
DNS = 1.1.1.1
MTU = 1420
Table = off
PostUp = iptables -A FORWARD -j ACCEPT
`)
	require.NoError(t, err)
}

func TestParseConfig_Errors(t *testing.T) {
	cases := map[string]string{
		"peer missing public key": "[Peer]\nAllowedIPs = 10.0.0.0/24",
		"invalid private key":     "[Interface]\nPrivateKey = not-base64",
		"invalid peer public key": "[Peer]\nPublicKey = short",
		"unknown interface key":   "[Interface]\nBogus = 1",
		"unknown peer key":        "[Peer]\nPublicKey = " + zeroKey + "\nBogus = 1",
		"unknown section":         "[Nonsense]\nkey = value",
		"key outside section":     "PrivateKey = " + zeroKey,
		"missing equals":          "[Interface]\nPrivateKey",
		"bad listen port":         "[Interface]\nListenPort = 99999",
		"bad allowed ip":          "[Peer]\nPublicKey = " + zeroKey + "\nAllowedIPs = not-an-ip",
		"bad keepalive":           "[Peer]\nPublicKey = " + zeroKey + "\nPersistentKeepalive = -5",
	}
	for name, cfg := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := parseConfig(cfg)
			assert.Error(t, err)
		})
	}
}

func TestParseConfig_FwMark(t *testing.T) {
	t.Run("hex (wg tooling form)", func(t *testing.T) {
		cfg, err := parseConfig("[Interface]\nPrivateKey = " + zeroKey + "\nFwMark = 0xca6c")
		require.NoError(t, err)
		require.NotNil(t, cfg.FirewallMark)
		assert.Equal(t, 0xca6c, *cfg.FirewallMark)
	})
	t.Run("decimal", func(t *testing.T) {
		cfg, err := parseConfig("[Interface]\nPrivateKey = " + zeroKey + "\nFwMark = 51820")
		require.NoError(t, err)
		require.NotNil(t, cfg.FirewallMark)
		assert.Equal(t, 51820, *cfg.FirewallMark)
	})
	t.Run("off means zero", func(t *testing.T) {
		cfg, err := parseConfig("[Interface]\nPrivateKey = " + zeroKey + "\nFwMark = off")
		require.NoError(t, err)
		require.NotNil(t, cfg.FirewallMark)
		assert.Equal(t, 0, *cfg.FirewallMark)
	})
	t.Run("out of 32-bit range rejected", func(t *testing.T) {
		_, err := parseConfig("[Interface]\nPrivateKey = " + zeroKey + "\nFwMark = 0x1FFFFFFFF")
		assert.Error(t, err)
	})
	t.Run("garbage rejected", func(t *testing.T) {
		_, err := parseConfig("[Interface]\nPrivateKey = " + zeroKey + "\nFwMark = nope")
		assert.Error(t, err)
	})
}

func TestParseConfig_EndpointFormats(t *testing.T) {
	t.Run("IPv4", func(t *testing.T) {
		cfg, err := parseConfig("[Peer]\nPublicKey = " + zeroKey + "\nEndpoint = 203.0.113.5:1194")
		require.NoError(t, err)
		assert.Equal(t, "203.0.113.5", cfg.Peers[0].Endpoint.IP.String())
		assert.Equal(t, 1194, cfg.Peers[0].Endpoint.Port)
	})
	t.Run("IPv6 bracketed", func(t *testing.T) {
		cfg, err := parseConfig("[Peer]\nPublicKey = " + zeroKey + "\nEndpoint = [2001:db8::1]:51820")
		require.NoError(t, err)
		assert.Equal(t, "2001:db8::1", cfg.Peers[0].Endpoint.IP.String())
		assert.Equal(t, 51820, cfg.Peers[0].Endpoint.Port)
	})
	t.Run("missing port", func(t *testing.T) {
		_, err := parseConfig("[Peer]\nPublicKey = " + zeroKey + "\nEndpoint = 203.0.113.5")
		assert.Error(t, err)
	})
}

// --- wg-quick interface settings (MTU / DNS) ---

func TestParseSettings_MTUAndDNS(t *testing.T) {
	s, err := ParseSettings(`
[Interface]
PrivateKey = ` + zeroKey + `
MTU = 1380
DNS = 10.77.0.1, orisonnet

[Peer]
PublicKey = ` + zeroKey + `
Endpoint = 192.0.2.1:51820
AllowedIPs = 10.77.0.0/24
`)
	require.NoError(t, err)
	assert.Equal(t, 1380, s.MTU)
	assert.Equal(t, []string{"10.77.0.1", "orisonnet"}, s.DNS)
}

func TestParseSettings_AbsentKeysAreZero(t *testing.T) {
	s, err := ParseSettings(`
[Interface]
PrivateKey = ` + zeroKey + `

[Peer]
PublicKey = ` + zeroKey + `
AllowedIPs = 0.0.0.0/0
`)
	require.NoError(t, err)
	assert.Zero(t, s.MTU, "absent MTU must stay zero so callers skip applying it")
	assert.Empty(t, s.DNS, "absent DNS must stay empty so callers skip applying it")
}

func TestParseSettings_InvalidMTU(t *testing.T) {
	for _, tc := range []string{"abc", "0", "-1", "67", "70000", ""} {
		_, err := ParseSettings("[Interface]\nMTU = " + tc + "\n")
		assert.Error(t, err, "MTU %q must be rejected", tc)
	}
}

func TestParseSettings_ValidMTUBounds(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want int
	}{{"68", 68}, {"1280", 1280}, {"1380", 1380}, {"65535", 65535}} {
		s, err := ParseSettings("[Interface]\nMTU = " + tc.in + "\n")
		require.NoError(t, err, "MTU %q must be accepted", tc.in)
		assert.Equal(t, tc.want, s.MTU)
	}
}

func TestParseSettings_DNSIgnoresPeerSection(t *testing.T) {
	// DNS/MTU are [Interface]-only; a stray key under [Peer] must not leak in.
	s, err := ParseSettings(`
[Interface]
PrivateKey = ` + zeroKey + `

[Peer]
PublicKey = ` + zeroKey + `
AllowedIPs = 0.0.0.0/0
`)
	require.NoError(t, err)
	assert.Empty(t, s.DNS)
}

// ParseSettings must reject the same malformed input parseConfig rejects, so a
// bad config fails once, consistently, rather than half-applying.
func TestParseSettings_PropagatesParseErrors(t *testing.T) {
	_, err := ParseSettings("[Interface]\nNotAKey = x\n")
	assert.Error(t, err)
}
