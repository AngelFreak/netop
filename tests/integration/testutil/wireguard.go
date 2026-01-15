//go:build integration

package testutil

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"
	"os/exec"
	"testing"

	"golang.org/x/crypto/curve25519"
)

// WireGuardInterface represents a WireGuard interface for testing.
type WireGuardInterface struct {
	Name       string
	PrivateKey string
	PublicKey  string
	Address    string
	ns         *TestNamespace
	t          *testing.T
}

// WireGuardPeer represents a WireGuard peer configuration.
type WireGuardPeer struct {
	PublicKey  string
	AllowedIPs string
	Endpoint   string
}

// NewWireGuardInterface creates a WireGuard interface in the given namespace.
// If ns is nil, creates in the host namespace.
func NewWireGuardInterface(t *testing.T, ns *TestNamespace, name, address string) *WireGuardInterface {
	t.Helper()
	SkipIfNotRoot(t)
	SkipIfNoWireGuard(t)
	SkipIfMissingCmd(t, "wg")

	// Generate key pair
	privateKey, publicKey, err := generateWireGuardKeyPair()
	if err != nil {
		t.Fatalf("failed to generate WireGuard keys: %v", err)
	}

	wg := &WireGuardInterface{
		Name:       name,
		PrivateKey: privateKey,
		PublicKey:  publicKey,
		Address:    address,
		ns:         ns,
		t:          t,
	}

	// Create the interface
	if err := wg.create(); err != nil {
		t.Fatalf("failed to create WireGuard interface: %v", err)
	}

	t.Cleanup(wg.cleanup)

	return wg
}

// create sets up the WireGuard interface.
func (wg *WireGuardInterface) create() error {
	var err error

	if wg.ns != nil {
		// Create in namespace
		err = wg.ns.Exec("ip", "link", "add", "dev", wg.Name, "type", "wireguard")
	} else {
		// Create in host namespace
		err = exec.Command("ip", "link", "add", "dev", wg.Name, "type", "wireguard").Run()
	}
	if err != nil {
		return fmt.Errorf("failed to create interface: %v", err)
	}

	// Write private key to temp file
	keyFile, err := os.CreateTemp("", "wg-key-*")
	if err != nil {
		return fmt.Errorf("failed to create key file: %v", err)
	}
	defer os.Remove(keyFile.Name())
	defer keyFile.Close()

	if _, err := keyFile.WriteString(wg.PrivateKey); err != nil {
		return fmt.Errorf("failed to write private key: %v", err)
	}
	keyFile.Close()

	// Set the private key
	if wg.ns != nil {
		err = wg.ns.Exec("wg", "set", wg.Name, "private-key", keyFile.Name())
	} else {
		err = exec.Command("wg", "set", wg.Name, "private-key", keyFile.Name()).Run()
	}
	if err != nil {
		return fmt.Errorf("failed to set private key: %v", err)
	}

	// Set address if specified
	if wg.Address != "" {
		if wg.ns != nil {
			err = wg.ns.Exec("ip", "addr", "add", wg.Address, "dev", wg.Name)
		} else {
			err = exec.Command("ip", "addr", "add", wg.Address, "dev", wg.Name).Run()
		}
		if err != nil {
			return fmt.Errorf("failed to set address: %v", err)
		}
	}

	// Bring up the interface
	if wg.ns != nil {
		err = wg.ns.Exec("ip", "link", "set", wg.Name, "up")
	} else {
		err = exec.Command("ip", "link", "set", wg.Name, "up").Run()
	}
	if err != nil {
		return fmt.Errorf("failed to bring up interface: %v", err)
	}

	return nil
}

// AddPeer adds a peer to the WireGuard interface.
func (wg *WireGuardInterface) AddPeer(peer WireGuardPeer) error {
	args := []string{"set", wg.Name, "peer", peer.PublicKey}

	if peer.AllowedIPs != "" {
		args = append(args, "allowed-ips", peer.AllowedIPs)
	}
	if peer.Endpoint != "" {
		args = append(args, "endpoint", peer.Endpoint)
	}

	var err error
	if wg.ns != nil {
		err = wg.ns.Exec("wg", args...)
	} else {
		err = exec.Command("wg", args...).Run()
	}
	if err != nil {
		return fmt.Errorf("failed to add peer: %v", err)
	}

	return nil
}

// Show returns the output of `wg show` for this interface.
func (wg *WireGuardInterface) Show() (string, error) {
	if wg.ns != nil {
		return wg.ns.ExecOutput("wg", "show", wg.Name)
	}
	output, err := exec.Command("wg", "show", wg.Name).CombinedOutput()
	return string(output), err
}

// cleanup removes the WireGuard interface.
func (wg *WireGuardInterface) cleanup() {
	if wg.ns != nil {
		_ = wg.ns.Exec("ip", "link", "del", wg.Name)
	} else {
		_ = exec.Command("ip", "link", "del", wg.Name).Run()
	}
}

// generateWireGuardKeyPair generates a WireGuard private/public key pair.
func generateWireGuardKeyPair() (privateKey, publicKey string, err error) {
	var private [32]byte
	if _, err := rand.Read(private[:]); err != nil {
		return "", "", fmt.Errorf("failed to generate random bytes: %v", err)
	}

	// Clamp the private key as per WireGuard spec
	private[0] &= 248
	private[31] &= 127
	private[31] |= 64

	// Derive public key using X25519 with the basepoint
	public, err := curve25519.X25519(private[:], curve25519.Basepoint)
	if err != nil {
		return "", "", fmt.Errorf("failed to derive public key: %v", err)
	}

	privateKey = base64.StdEncoding.EncodeToString(private[:])
	publicKey = base64.StdEncoding.EncodeToString(public)

	return privateKey, publicKey, nil
}

// CreateWireGuardPair creates two connected WireGuard interfaces for testing.
// Returns the server and client interfaces.
func CreateWireGuardPair(t *testing.T, serverNS, clientNS *TestNamespace) (*WireGuardInterface, *WireGuardInterface) {
	t.Helper()

	server := NewWireGuardInterface(t, serverNS, "wg-server", "10.200.200.1/24")
	client := NewWireGuardInterface(t, clientNS, "wg-client", "10.200.200.2/24")

	// Add each as peer to the other
	err := server.AddPeer(WireGuardPeer{
		PublicKey:  client.PublicKey,
		AllowedIPs: "10.200.200.2/32",
	})
	if err != nil {
		t.Fatalf("failed to add client as peer to server: %v", err)
	}

	err = client.AddPeer(WireGuardPeer{
		PublicKey:  server.PublicKey,
		AllowedIPs: "10.200.200.1/32",
	})
	if err != nil {
		t.Fatalf("failed to add server as peer to client: %v", err)
	}

	return server, client
}
