package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Reserved sections are not networks, so completion must not offer them.
func TestGetNetworkNames_SkipsReservedSections(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	yaml := "common:\n  dns: 1.1.1.1\nvpn:\n  work:\n    type: openvpn\ntunnel:\n  app:\n    host: box\n    forward: [3000]\nhome:\n  ssid: Home\n"
	require.NoError(t, os.WriteFile(path, []byte(yaml), 0600))
	saved := configPath
	configPath = path
	t.Cleanup(func() { configPath = saved })

	assert.ElementsMatch(t, []string{"home"}, getNetworkNames())
}
