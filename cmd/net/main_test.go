package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCommandNeedsRootArgs(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want bool
	}{
		{"no args (default connect) needs root", []string{}, true},
		{"status is exempt", []string{"status"}, false},
		{"show is exempt", []string{"show"}, false},
		{"list is exempt", []string{"list"}, false},
		{"help is exempt", []string{"--help"}, false},
		{"connect needs root", []string{"home"}, true},
		{"vpn needs root", []string{"vpn"}, true},
		// The bug: a value-taking flag's value must not be read as the subcommand.
		{"--iface value then status stays exempt", []string{"--iface", "wlp1s0", "status"}, false},
		{"--config value then show stays exempt", []string{"--config", "/tmp/c.yaml", "show"}, false},
		{"--iface=value equals form then status stays exempt", []string{"--iface=wlp1s0", "status"}, false},
		{"--iface value then connect still needs root", []string{"--iface", "wlp1s0", "home"}, true},
		{"debug flag then status stays exempt", []string{"--debug", "status"}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, commandNeedsRootArgs(tt.args))
		})
	}
}

func TestSelectDefaultInterface(t *testing.T) {
	// Build a fake /sys/class/net with a helper.
	mkIface := func(root, name, operstate string, wireless bool) {
		dir := filepath.Join(root, name)
		os.MkdirAll(dir, 0755)
		os.WriteFile(filepath.Join(dir, "operstate"), []byte(operstate+"\n"), 0644)
		if wireless {
			os.Mkdir(filepath.Join(dir, "wireless"), 0755)
		}
	}

	t.Run("prefers up wireless over up wired", func(t *testing.T) {
		root := t.TempDir()
		mkIface(root, "lo", "unknown", false)
		mkIface(root, "eth0", "up", false)
		mkIface(root, "wlp1s0", "up", true)
		iface, why := selectDefaultInterface(root)
		assert.Equal(t, "wlp1s0", iface)
		assert.Equal(t, "up wireless", why)
	})

	t.Run("ignores VPN/virtual interfaces, picks the real wireless", func(t *testing.T) {
		root := t.TempDir()
		mkIface(root, "wg0", "unknown", false)
		mkIface(root, "tailscale0", "unknown", false)
		mkIface(root, "wt0", "unknown", false)
		mkIface(root, "wlp1s0", "up", true)
		iface, _ := selectDefaultInterface(root)
		assert.Equal(t, "wlp1s0", iface)
	})

	t.Run("falls back to up wired when no wireless", func(t *testing.T) {
		root := t.TempDir()
		mkIface(root, "enp3s0", "up", false)
		iface, why := selectDefaultInterface(root)
		assert.Equal(t, "enp3s0", iface)
		assert.Equal(t, "up wired", why)
	})

	t.Run("down wireless still beats wired when both present", func(t *testing.T) {
		root := t.TempDir()
		mkIface(root, "eth0", "up", false)
		mkIface(root, "wlan0", "down", true)
		iface, why := selectDefaultInterface(root)
		assert.Equal(t, "wlan0", iface)
		assert.Equal(t, "wireless", why)
	})

	t.Run("empty sysfs falls back to wlan0", func(t *testing.T) {
		iface, why := selectDefaultInterface(filepath.Join(t.TempDir(), "does-not-exist"))
		assert.Equal(t, "wlan0", iface)
		assert.Equal(t, "", why)
	})
}
