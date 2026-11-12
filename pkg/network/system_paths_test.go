package network

import (
	"testing"

	"github.com/angelfreak/net/pkg/types"
	"github.com/stretchr/testify/assert"
)

// CI runs this package's tests as root (`sudo go test -tags=integration`).
// Tests that reached the real /etc/resolv.conf overwrote the runner's DNS
// ("# Waiting for DHCP", or nameserver 1.1.1.1 locked immutable), so the
// runner could no longer reach GitHub and the job hung until timeout (#66).
// TestMain points the package defaults at temp files; every Manager, from
// NewManager or a bare struct literal, must pick them up.
func TestTestsNeverUseTheSystemDNSFiles(t *testing.T) {
	for name, m := range map[string]*Manager{
		"NewManager":     NewManager(newMockExecutor(), &mockLogger{}, nil),
		"struct literal": {},
	} {
		assert.NotEqual(t, "/etc/resolv.conf", m.resolvConf(), name)
		assert.NotEqual(t, types.DNSOwnedPath, m.dnsOwnedPath(), name)
	}
}

// The override is test-only: outside tests the defaults are the system
// paths, and the DNS marker is the one net's DHCP hooks check.
func TestProductionDefaultsAreTheSystemDNSFiles(t *testing.T) {
	assert.Equal(t, "/etc/resolv.conf", productionResolvConf)
	assert.Equal(t, types.DNSOwnedPath, productionDNSOwned)
}
