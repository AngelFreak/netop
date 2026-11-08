package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTunnelConfigParsing(t *testing.T) {
	cfg, err := loadPortalConfig(t, `
tunnel:
  app:
    host: user@100.72.140.241
    port: 2222
    identity: ~/.ssh/id_ed25519
    forward:
      - 3000
      - 13000:5000
      - 5432:db.internal:5432
`)
	require.NoError(t, err)
	tun, ok := cfg.Tunnel["app"]
	require.True(t, ok)
	assert.Equal(t, "user@100.72.140.241", tun.Host)
	assert.Equal(t, 2222, tun.Port)
	assert.Equal(t, "~/.ssh/id_ed25519", tun.Identity)
	assert.Equal(t, []string{"3000", "13000:5000", "5432:db.internal:5432"}, tun.Forward)
}

func TestTunnelSectionIsNotANetwork(t *testing.T) {
	cfg, err := loadPortalConfig(t, "\ntunnel:\n  app:\n    host: box\n    forward: [3000]\n")
	require.NoError(t, err)
	assert.NotContains(t, cfg.Networks, "tunnel")
}

func TestTunnelNullSectionAllowed(t *testing.T) {
	_, err := loadPortalConfig(t, "\ntunnel:\n")
	assert.NoError(t, err)
}

func TestTunnelConfigRejected(t *testing.T) {
	tests := []struct {
		name string
		yaml string
		want string
	}{
		{"unknown field", "tunnel:\n  app:\n    hots: box\n    forward: [3000]\n", "hots"},
		{"missing host", "tunnel:\n  app:\n    forward: [3000]\n", "tunnel.app.host"},
		{"non-string host", "tunnel:\n  app:\n    host: [a]\n    forward: [3000]\n", "tunnel.app.host"},
		{"option-like host", "tunnel:\n  app:\n    host: -oProxyCommand=sh\n    forward: [3000]\n", "tunnel.app.host"},
		{"missing forward", "tunnel:\n  app:\n    host: box\n", "tunnel.app.forward"},
		{"empty forward", "tunnel:\n  app:\n    host: box\n    forward: []\n", "tunnel.app.forward"},
		{"scalar forward", "tunnel:\n  app:\n    host: box\n    forward: 3000\n", "tunnel.app.forward"},
		{"bad forward spec", "tunnel:\n  app:\n    host: box\n    forward: [abc]\n", "tunnel.app.forward"},
		{"port zero", "tunnel:\n  app:\n    host: box\n    port: 0\n    forward: [3000]\n", "tunnel.app.port"},
		{"port too big", "tunnel:\n  app:\n    host: box\n    port: 70000\n    forward: [3000]\n", "tunnel.app.port"},
		{"port not a number", "tunnel:\n  app:\n    host: box\n    port: ssh\n    forward: [3000]\n", "tunnel.app.port"},
		{"non-string identity", "tunnel:\n  app:\n    host: box\n    identity: [k]\n    forward: [3000]\n", "tunnel.app.identity"},
		{"scalar entry", "tunnel:\n  app: box\n", "tunnel.app"},
		{"scalar section", "tunnel: box\n", "tunnel"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := loadPortalConfig(t, tt.yaml)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.want)
		})
	}
}
