package types

import (
	"fmt"
	"net"
	"strconv"
	"strings"
)

// TunnelConfig is a configured SSH tunnel (the tunnel: section).
type TunnelConfig struct {
	Host     string   `yaml:"host" mapstructure:"host"`         // ssh destination: user@host, alias, or IP
	Port     int      `yaml:"port" mapstructure:"port"`         // ssh port (ssh -p); 0 means ssh's default
	Identity string   `yaml:"identity" mapstructure:"identity"` // private key (ssh -i); empty means ssh's default
	Forward  []string `yaml:"forward" mapstructure:"forward"`   // forward specs, see ParseForward
}

// Forward is one local port forward: localhost:LocalPort reaches
// RemoteHost:RemotePort as seen from the SSH server.
type Forward struct {
	LocalPort  int    `json:"local_port"`
	RemoteHost string `json:"remote_host"`
	RemotePort int    `json:"remote_port"`
	// Pinned means the user chose LocalPort explicitly, so it must not be
	// moved to a free port when busy.
	Pinned bool `json:"-"`
}

// SSHArg renders the forward as an ssh -L argument, bound to loopback only.
func (f Forward) SSHArg() string {
	host := f.RemoteHost
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	return fmt.Sprintf("127.0.0.1:%d:%s:%d", f.LocalPort, host, f.RemotePort)
}

// String renders the forward for people.
func (f Forward) String() string {
	return fmt.Sprintf("localhost:%d → %s", f.LocalPort, net.JoinHostPort(f.RemoteHost, strconv.Itoa(f.RemotePort)))
}

// ParseForward parses a forward spec:
//
//	3000                   local 3000 → 127.0.0.1:3000 on the SSH host
//	13000:3000             local 13000 → 127.0.0.1:3000 (local port pinned)
//	5432:db.internal:5432  local 5432 → db.internal:5432 (local port pinned)
func ParseForward(spec string) (Forward, error) {
	spec = strings.TrimSpace(spec)
	local, rest, hasRemote := strings.Cut(spec, ":")
	localPort, err := parsePort(local)
	if err != nil {
		return Forward{}, fmt.Errorf("invalid forward %q: %w", spec, err)
	}
	if !hasRemote {
		return Forward{LocalPort: localPort, RemoteHost: "127.0.0.1", RemotePort: localPort}, nil
	}

	remoteHost, remotePortStr := "127.0.0.1", rest
	if _, err := strconv.Atoi(rest); err != nil {
		remoteHost, remotePortStr, err = net.SplitHostPort(rest)
		if err != nil {
			return Forward{}, fmt.Errorf("invalid forward %q: want PORT, LOCAL:PORT or LOCAL:HOST:PORT", spec)
		}
		if err := validateForwardHost(remoteHost); err != nil {
			return Forward{}, fmt.Errorf("invalid forward %q: %w", spec, err)
		}
	}
	remotePort, err := parsePort(remotePortStr)
	if err != nil {
		return Forward{}, fmt.Errorf("invalid forward %q: %w", spec, err)
	}
	return Forward{LocalPort: localPort, RemoteHost: remoteHost, RemotePort: remotePort, Pinned: true}, nil
}

func parsePort(s string) (int, error) {
	port, err := strconv.Atoi(s)
	if err != nil || port < 1 || port > 65535 {
		return 0, fmt.Errorf("port %q must be a number from 1 to 65535", s)
	}
	return port, nil
}

// validateForwardHost accepts hostnames and IP addresses only, so the value
// can never be read as an ssh option or break the -L argument apart.
func validateForwardHost(host string) error {
	if host == "" || strings.HasPrefix(host, "-") {
		return fmt.Errorf("invalid remote host %q", host)
	}
	for _, r := range host {
		ok := r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' ||
			r == '.' || r == '-' || r == '_' || r == ':'
		if !ok {
			return fmt.Errorf("invalid remote host %q", host)
		}
	}
	return nil
}

// ValidateSSHHost checks an ssh destination (user@host, alias or IP). It
// must not start with "-", where ssh would read it as an option, and must be
// visible ASCII with no whitespace.
func ValidateSSHHost(host string) error {
	if host == "" {
		return fmt.Errorf("ssh host is empty")
	}
	if strings.HasPrefix(host, "-") {
		return fmt.Errorf("ssh host %q must not start with '-'", host)
	}
	for _, r := range host {
		if r < 0x21 || r > 0x7e {
			return fmt.Errorf("ssh host %q must be visible ASCII with no spaces", host)
		}
	}
	return nil
}

// TunnelSpec describes a tunnel to start.
type TunnelSpec struct {
	Name     string
	Host     string
	Port     int
	Identity string
	Forwards []Forward
	AdHoc    bool
}

// TunnelStatus describes a tracked tunnel.
type TunnelStatus struct {
	Name     string    `json:"name"`
	Host     string    `json:"host"`
	Forwards []Forward `json:"forwards"`
	Up       bool      `json:"up"`
	AdHoc    bool      `json:"ad_hoc"`
	PID      int       `json:"pid,omitempty"`
	// Warnings are problems found after a successful start, such as nothing
	// listening on a forward's remote port.
	Warnings []string `json:"warnings,omitempty"`
}

// TunnelManager runs SSH port-forward tunnels.
type TunnelManager interface {
	// Start brings the tunnel up. A tunnel of the same name that is already
	// up is left alone and returned as is.
	Start(spec TunnelSpec) (*TunnelStatus, error)
	// Stop stops the tunnel named target, or the one with a local port equal
	// to target, or every tunnel when target is "". It returns the stopped
	// tunnels; an unknown target wraps ErrNotFound.
	Stop(target string) ([]TunnelStatus, error)
	// List returns every tracked tunnel, up or not.
	List() ([]TunnelStatus, error)
}
