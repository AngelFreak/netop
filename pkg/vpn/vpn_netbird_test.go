package vpn

import (
	"testing"

	"github.com/angelfreak/net/pkg/types"
	"github.com/stretchr/testify/assert"
)

func TestNetBirdConfigFields(t *testing.T) {
	config := types.VPNConfig{
		Type:          "netbird",
		SetupKey:      "XXXXXXXX",
		ManagementURL: "https://api.netbird.io",
	}
	assert.Equal(t, "netbird", config.Type)
	assert.Equal(t, "XXXXXXXX", config.SetupKey)
	assert.Equal(t, "https://api.netbird.io", config.ManagementURL)
}
