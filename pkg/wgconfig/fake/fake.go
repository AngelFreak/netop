// Package fake provides an in-memory WireGuardConfigurator for tests.
package fake

// Configurator is an in-memory fake of types.WireGuardConfigurator that records
// calls instead of touching the kernel wireguard API.
type Configurator struct {
	// ConfiguredIface / ConfiguredConfig capture the last Configure call.
	ConfiguredIface  string
	ConfiguredConfig string
	Configured       bool
	// ConfigureErr, if set, is returned by Configure.
	ConfigureErr error

	// Peers maps interface name -> whether HasPeers should report peers.
	Peers map[string]bool
	// HasPeersErr, if set, is returned by HasPeers.
	HasPeersErr error
}

// New returns a ready-to-use fake.
func New() *Configurator {
	return &Configurator{Peers: map[string]bool{}}
}

// Configure records the call and returns ConfigureErr.
func (c *Configurator) Configure(iface, config string) error {
	if c.ConfigureErr != nil {
		return c.ConfigureErr
	}
	c.ConfiguredIface = iface
	c.ConfiguredConfig = config
	c.Configured = true
	return nil
}

// HasPeers reports the recorded state for iface (default false) and
// HasPeersErr.
func (c *Configurator) HasPeers(iface string) (bool, error) {
	if c.HasPeersErr != nil {
		return false, c.HasPeersErr
	}
	return c.Peers[iface], nil
}
