// Package testsshd provides an in-process SSH server for tests. It serves
// only port forwards ("direct-tcpip" channels), so tests can drive the real
// ssh client end to end without an sshd installed.
package testsshd

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

// Server is a running test SSH server. Its ssh_config defines host aliases:
// "testhost" (trusted host key, accepted client key), "unknownhost" (host
// key not trusted) and "badkeyhost" (client key the server refuses).
type Server struct {
	Port       int
	ConfigPath string // pass to ssh with -F
}

// Start runs a server until the test ends. It skips the test when the ssh
// client is not installed.
func Start(t testing.TB) *Server {
	t.Helper()
	if _, err := exec.LookPath("ssh"); err != nil {
		t.Skip("ssh client not installed")
	}
	dir := t.TempDir()

	_, hostPriv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	hostSigner, err := ssh.NewSignerFromKey(hostPriv)
	require.NoError(t, err)

	_, strangerPriv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	strangerBlock, err := ssh.MarshalPrivateKey(strangerPriv, "")
	require.NoError(t, err)
	strangerKeyPath := filepath.Join(dir, "id_stranger")
	require.NoError(t, os.WriteFile(strangerKeyPath, pem.EncodeToMemory(strangerBlock), 0600))

	clientPub, clientPriv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	clientSSHPub, err := ssh.NewPublicKey(clientPub)
	require.NoError(t, err)
	block, err := ssh.MarshalPrivateKey(clientPriv, "")
	require.NoError(t, err)
	keyPath := filepath.Join(dir, "id_ed25519")
	require.NoError(t, os.WriteFile(keyPath, pem.EncodeToMemory(block), 0600))

	cfg := &ssh.ServerConfig{
		PublicKeyCallback: func(_ ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			if string(key.Marshal()) == string(clientSSHPub.Marshal()) {
				return nil, nil
			}
			return nil, fmt.Errorf("unknown key")
		},
	}
	cfg.AddHostKey(hostSigner)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	var wg sync.WaitGroup
	t.Cleanup(func() {
		ln.Close()
		wg.Wait()
	})
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				serveSSHConn(conn, cfg)
			}()
		}
	}()

	port := ln.Addr().(*net.TCPAddr).Port
	knownHosts := filepath.Join(dir, "known_hosts")
	hostLine := fmt.Sprintf("[127.0.0.1]:%d %s", port, ssh.MarshalAuthorizedKey(hostSigner.PublicKey()))
	require.NoError(t, os.WriteFile(knownHosts, []byte(hostLine), 0600))

	configPath := filepath.Join(dir, "ssh_config")
	sshConfig := fmt.Sprintf(`Host testhost
  HostName 127.0.0.1
  Port %d
  User tester
  IdentityFile %s
  IdentitiesOnly yes
  UserKnownHostsFile %s
  StrictHostKeyChecking yes
Host unknownhost
  HostName 127.0.0.1
  Port %d
  IdentityFile %s
  IdentitiesOnly yes
  UserKnownHostsFile /dev/null
  StrictHostKeyChecking yes
Host badkeyhost
  HostName 127.0.0.1
  Port %d
  User tester
  IdentityFile %s
  IdentitiesOnly yes
  UserKnownHostsFile %s
  StrictHostKeyChecking yes
`, port, keyPath, knownHosts, port, keyPath, port, strangerKeyPath, knownHosts)
	require.NoError(t, os.WriteFile(configPath, []byte(sshConfig), 0600))

	return &Server{Port: port, ConfigPath: configPath}
}

// serveSSHConn handles one client: global requests (keepalives) get a reply,
// direct-tcpip channels are dialed and piped, everything else is rejected.
func serveSSHConn(conn net.Conn, cfg *ssh.ServerConfig) {
	defer conn.Close()
	sconn, chans, reqs, err := ssh.NewServerConn(conn, cfg)
	if err != nil {
		return
	}
	defer sconn.Close()
	go ssh.DiscardRequests(reqs)
	for nc := range chans {
		if nc.ChannelType() != "direct-tcpip" {
			nc.Reject(ssh.UnknownChannelType, "only port forwarding is served")
			continue
		}
		target, ok := parseDirectTCPIP(nc.ExtraData())
		if !ok {
			nc.Reject(ssh.ConnectionFailed, "bad direct-tcpip payload")
			continue
		}
		dst, err := net.Dial("tcp", target)
		if err != nil {
			nc.Reject(ssh.ConnectionFailed, "connect failed: "+err.Error())
			continue
		}
		ch, chReqs, err := nc.Accept()
		if err != nil {
			dst.Close()
			continue
		}
		go ssh.DiscardRequests(chReqs)
		go pipe(ch, dst)
	}
}

func pipe(ch ssh.Channel, dst net.Conn) {
	defer ch.Close()
	defer dst.Close()
	done := make(chan struct{}, 2)
	go func() { io.Copy(dst, ch); done <- struct{}{} }()
	go func() { io.Copy(ch, dst); done <- struct{}{} }()
	<-done
}

// parseDirectTCPIP decodes the RFC 4254 7.2 payload: host string, port
// uint32, originator host string, originator port uint32.
func parseDirectTCPIP(b []byte) (string, bool) {
	if len(b) < 4 {
		return "", false
	}
	n := binary.BigEndian.Uint32(b)
	if uint32(len(b)) < 4+n+4 {
		return "", false
	}
	host := string(b[4 : 4+n])
	port := binary.BigEndian.Uint32(b[4+n:])
	return net.JoinHostPort(host, strconv.Itoa(int(port))), true
}
