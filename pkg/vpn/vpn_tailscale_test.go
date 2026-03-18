package vpn

import (
	"testing"

	"github.com/angelfreak/net/pkg/types"
	"github.com/stretchr/testify/assert"
)

func TestTailscaleConfigFields(t *testing.T) {
	config := types.VPNConfig{
		Type:         "tailscale",
		AuthKey:      "tskey-auth-xxxxx",
		ExitNode:     "us-east-1",
		AcceptRoutes: true,
	}
	assert.Equal(t, "tailscale", config.Type)
	assert.Equal(t, "tskey-auth-xxxxx", config.AuthKey)
	assert.Equal(t, "us-east-1", config.ExitNode)
	assert.True(t, config.AcceptRoutes)
}
