package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// "dns: 8.8.8.8, 8.8.4.4" is how people write two servers (config.example
// does). Splitting on "," alone kept the space, and SetDNS then dropped
// " 8.8.4.4" as an invalid IP, so only the first server was ever used.
func TestLoadConfig_CommaSeparatedListValuesAreTrimmed(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	require.NoError(t, os.WriteFile(path, []byte(`common:
  dns: 8.8.8.8, 8.8.4.4

cafe:
  ssid: Cafe
  dns: 1.1.1.1 ,  9.9.9.9
`), 0600))

	manager := NewManager(&mockLogger{})
	config, err := manager.LoadConfig(path)
	require.NoError(t, err)

	assert.Equal(t, []string{"8.8.8.8", "8.8.4.4"}, config.Common.DNS)
	assert.Equal(t, []string{"1.1.1.1", "9.9.9.9"}, config.Networks["cafe"].DNS)

	// The lazy per-network path decodes separately and must agree.
	cafe, err := manager.GetNetworkConfig("cafe")
	require.NoError(t, err)
	assert.Equal(t, []string{"1.1.1.1", "9.9.9.9"}, cafe.DNS)
}

// The example config is what install.sh puts in place for a new user, so it
// has to load.
func TestConfigExample_Loads(t *testing.T) {
	manager := NewManager(&mockLogger{})
	config, err := manager.LoadConfig(filepath.Join("..", "..", "config.example"))
	require.NoError(t, err)
	assert.Equal(t, []string{"8.8.8.8", "8.8.4.4"}, config.Common.DNS)
}
