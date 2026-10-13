// Package tunnel runs SSH port-forward tunnels. Each tunnel is one ssh
// master process, started in the background with -f and tracked through its
// control socket, so net needs no daemon and no PID files.
package tunnel

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/angelfreak/net/pkg/system"
	"github.com/angelfreak/net/pkg/types"
)

// ErrAuthFailed marks an SSH server refusing the login, so callers can add
// context such as sudo having dropped the user's ssh-agent.
var ErrAuthFailed = errors.New("ssh login refused")

const (
	// maxIDLen caps file names so control socket paths fit maxSocketPath
	// in every default tunnel directory.
	maxIDLen = 48
	// maxSocketPath is the longest control socket path ssh can create: it
	// binds "<path>.<16 random chars>" first, and sun_path holds 104 bytes
	// on macOS (108 on Linux).
	maxSocketPath = 104 - 17

	// portShift is where a busy local port moves first: 3000 → 13000.
	portShift = 10000

	startTimeout   = 30 * time.Second
	controlTimeout = 5 * time.Second
	stopWait       = 2 * time.Second
)

// Manager implements types.TunnelManager.
type Manager struct {
	executor types.SystemExecutor
	logger   types.Logger
	dir      string // state directory: <id>.json, <id>.sock, <id>.log

	sshConfig   string              // ssh -F file; tests point ssh at their own server
	portFree    func(port int) bool // whether a loopback port can be bound
	anyFreePort func() (int, error) // a loopback port the kernel picks
	probeWait   time.Duration       // how long the remote-port probe waits for a refusal
}

// NewManager returns a Manager keeping its state in dir (see DefaultDir).
func NewManager(executor types.SystemExecutor, logger types.Logger, dir string) *Manager {
	return &Manager{
		executor:    executor,
		logger:      logger,
		dir:         dir,
		portFree:    loopbackPortFree,
		anyFreePort: loopbackAnyFreePort,
		probeWait:   500 * time.Millisecond,
	}
}

// state is what net remembers about a tunnel between invocations.
type state struct {
	Name     string          `json:"name"`
	Host     string          `json:"host"`
	Forwards []types.Forward `json:"forwards"`
	AdHoc    bool            `json:"ad_hoc"`
	Started  time.Time       `json:"started"`
}

func (s state) status(up bool) types.TunnelStatus {
	return types.TunnelStatus{Name: s.Name, Host: s.Host, Forwards: s.Forwards, Up: up, AdHoc: s.AdHoc}
}

// matches reports whether target names this tunnel or one of its local ports.
func (s state) matches(target string) bool {
	if strings.EqualFold(s.Name, target) {
		return true
	}
	port, err := strconv.Atoi(target)
	if err != nil {
		return false
	}
	return slices.ContainsFunc(s.Forwards, func(f types.Forward) bool { return f.LocalPort == port })
}

// AdHocName names an ad-hoc tunnel after its host and remote ports, e.g.
// "user@box:3000,5432".
func AdHocName(host string, forwards []types.Forward) string {
	ports := make([]string, len(forwards))
	for i, f := range forwards {
		ports[i] = strconv.Itoa(f.RemotePort)
	}
	return host + ":" + strings.Join(ports, ",")
}

// Start brings a tunnel up. See types.TunnelManager.
func (m *Manager) Start(spec types.TunnelSpec) (*types.TunnelStatus, error) {
	if spec.Name == "" {
		return nil, fmt.Errorf("tunnel has no name")
	}
	if err := types.ValidateSSHHost(spec.Host); err != nil {
		return nil, err
	}
	if len(spec.Forwards) == 0 {
		return nil, fmt.Errorf("tunnel %q has no ports to forward", spec.Name)
	}
	id := tunnelID(spec.Name)
	if sock := m.path(id, ".sock"); len(sock) > maxSocketPath {
		return nil, fmt.Errorf("tunnel socket path %s is too long for ssh; use a shorter tunnel name", sock)
	}
	if err := ensureDir(m.dir); err != nil {
		return nil, err
	}

	if existing, err := m.readState(id); err == nil {
		if existing.Name != spec.Name {
			return nil, fmt.Errorf("tunnel %q clashes with tunnel %q; rename one of them", spec.Name, existing.Name)
		}
		if m.alive(existing.Host, id) {
			st := existing.status(true)
			return &st, nil
		}
	}
	m.removeFiles(id) // leftovers of a dropped tunnel

	forwards, err := m.assignPorts(spec.Forwards)
	if err != nil {
		return nil, err
	}
	spec.Forwards = forwards

	st := state{Name: spec.Name, Host: spec.Host, Forwards: forwards, AdHoc: spec.AdHoc, Started: time.Now()}
	if err := m.writeState(id, st); err != nil {
		return nil, err
	}
	m.logger.Debug("Starting SSH tunnel", "name", spec.Name, "host", spec.Host)
	if _, err := m.executor.ExecuteWithTimeout(startTimeout, "ssh", m.startArgs(spec, id)...); err != nil {
		log, _ := os.ReadFile(m.path(id, ".log"))
		m.removeFiles(id)
		return nil, classify(string(log), spec.Host, err)
	}

	status := st.status(true)
	status.Warnings = m.probe(spec.Host, forwards, m.path(id, ".log"))
	return &status, nil
}

// Stop stops tunnels. See types.TunnelManager.
func (m *Manager) Stop(target string) ([]types.TunnelStatus, error) {
	states, err := m.states()
	if err != nil {
		return nil, err
	}
	var stopped []types.TunnelStatus
	for id, st := range states {
		if target != "" && !st.matches(target) {
			continue
		}
		if m.alive(st.Host, id) {
			if _, err := m.executor.ExecuteWithTimeout(controlTimeout, "ssh", m.controlArgs(id, "exit", st.Host)...); err != nil {
				return stopped, fmt.Errorf("stopping tunnel %q: %w", st.Name, err)
			}
			m.waitDown(st.Host, id)
		}
		m.removeFiles(id)
		stopped = append(stopped, st.status(false))
	}
	if target != "" && len(stopped) == 0 {
		return nil, fmt.Errorf("no tunnel %q: %w", target, types.ErrNotFound)
	}
	sortByName(stopped)
	return stopped, nil
}

// List returns every tracked tunnel. A tunnel whose ssh has died is listed
// as down until it is stopped or started again.
func (m *Manager) List() ([]types.TunnelStatus, error) {
	states, err := m.states()
	if err != nil {
		return nil, err
	}
	list := []types.TunnelStatus{}
	for id, st := range states {
		list = append(list, st.status(m.alive(st.Host, id)))
	}
	sortByName(list)
	return list, nil
}

func sortByName(list []types.TunnelStatus) {
	sort.Slice(list, func(i, j int) bool { return list[i].Name < list[j].Name })
}

// startArgs builds the ssh command line for a tunnel. The host comes last,
// after "--", so it can never be read as an option.
func (m *Manager) startArgs(spec types.TunnelSpec, id string) []string {
	args := m.configArgs()
	args = append(args,
		"-f", "-N", "-M", "-S", m.path(id, ".sock"), "-E", m.path(id, ".log"),
		"-o", "BatchMode=yes", "-o", "ExitOnForwardFailure=yes",
		"-o", "ServerAliveInterval=15", "-o", "ServerAliveCountMax=3",
		"-o", "ControlPersist=no", "-o", "ConnectTimeout=10",
	)
	if spec.Port != 0 {
		args = append(args, "-p", strconv.Itoa(spec.Port))
	}
	if spec.Identity != "" {
		args = append(args, "-i", spec.Identity)
	}
	for _, f := range spec.Forwards {
		args = append(args, "-L", f.SSHArg())
	}
	return append(args, "--", spec.Host)
}

// controlArgs builds an "ssh -O <op>" command for a tunnel's control socket.
func (m *Manager) controlArgs(id, op, host string) []string {
	return append(m.configArgs(), "-S", m.path(id, ".sock"), "-O", op, "--", host)
}

func (m *Manager) configArgs() []string {
	if m.sshConfig == "" {
		return nil
	}
	return []string{"-F", m.sshConfig}
}

// alive asks the tunnel's ssh master whether it is still running.
func (m *Manager) alive(host, id string) bool {
	_, err := m.executor.ExecuteWithTimeout(controlTimeout, "ssh", m.controlArgs(id, "check", host)...)
	return err == nil
}

// waitDown waits for an exiting ssh master to go away, so its ports are
// closed when Stop returns.
func (m *Manager) waitDown(host, id string) {
	deadline := time.Now().Add(stopWait)
	for m.alive(host, id) && time.Now().Before(deadline) {
		time.Sleep(50 * time.Millisecond)
	}
}

// assignPorts picks the local port of every forward. A busy port moves to
// port+10000, then to any free port, unless the user pinned it. The input
// is not modified.
func (m *Manager) assignPorts(in []types.Forward) ([]types.Forward, error) {
	out := slices.Clone(in)
	taken := map[int]bool{}
	free := func(port int) bool {
		return port >= 1 && port <= 65535 && !taken[port] && m.portFree(port)
	}
	for i := range out {
		f := &out[i]
		switch {
		case free(f.LocalPort):
		case f.Pinned:
			return nil, fmt.Errorf("local port %d is already in use", f.LocalPort)
		case free(f.LocalPort + portShift):
			f.LocalPort += portShift
		default:
			port, err := m.pickFreePort(taken)
			if err != nil {
				return nil, err
			}
			f.LocalPort = port
		}
		taken[f.LocalPort] = true
	}
	return out, nil
}

func (m *Manager) pickFreePort(taken map[int]bool) (int, error) {
	for range 10 {
		port, err := m.anyFreePort()
		if err != nil {
			return 0, fmt.Errorf("finding a free local port: %w", err)
		}
		if !taken[port] {
			return port, nil
		}
	}
	return 0, fmt.Errorf("finding a free local port: none available")
}

func loopbackPortFree(port int) bool {
	ln, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	if err != nil {
		return false
	}
	ln.Close()
	return true
}

func loopbackAnyFreePort() (int, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port, nil
}

// probe connects once through each forward and returns a warning for every
// forward whose remote port refused the connection. ssh accepts the local
// connection either way; a refusal shows as an immediate close plus an
// "open failed" line in its log.
func (m *Manager) probe(host string, forwards []types.Forward, logPath string) []string {
	var warnings []string
	for _, f := range forwards {
		if m.remoteRefused(f, logPath) {
			warnings = append(warnings, fmt.Sprintf("connected, but nothing is listening on %s on %s",
				net.JoinHostPort(f.RemoteHost, strconv.Itoa(f.RemotePort)), host))
		}
	}
	return warnings
}

func (m *Manager) remoteRefused(f types.Forward, logPath string) bool {
	offset := fileSize(logPath)
	conn, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(f.LocalPort)), time.Second)
	if err != nil {
		return false
	}
	_ = conn.SetReadDeadline(time.Now().Add(m.probeWait))
	_, err = conn.Read(make([]byte, 1))
	conn.Close()
	if !errors.Is(err, io.EOF) {
		return false // data or a timeout: something on the remote end accepted
	}
	deadline := time.Now().Add(m.probeWait)
	for {
		if strings.Contains(readFrom(logPath, offset), "open failed") {
			return true
		}
		if time.Now().After(deadline) {
			return false
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func fileSize(path string) int64 {
	info, err := os.Stat(path)
	if err != nil {
		return 0
	}
	return info.Size()
}

func readFrom(path string, offset int64) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	if _, err := f.Seek(offset, io.SeekStart); err != nil {
		return ""
	}
	b, _ := io.ReadAll(f)
	return string(b)
}

var bindFailure = regexp.MustCompile(`bind \[[^\]]*\]:(\d+): Address already in use`)

var unreachable = []string{
	"Could not resolve hostname", "Connection refused", "timed out",
	"No route to host", "Network is unreachable",
}

// classify turns ssh's log into an error that says what to do. Log text can
// carry a server banner, so it is sanitized before it reaches a terminal.
func classify(log, host string, execErr error) error {
	switch {
	case strings.Contains(log, "Host key verification failed"):
		return fmt.Errorf("the host key for %s is not trusted yet; run 'ssh %s' once to check and accept it", host, host)
	case strings.Contains(log, "Permission denied"):
		return fmt.Errorf("%s refused the login; tunnels need key or ssh-agent auth, not a password (test with 'ssh %s'): %w", host, host, ErrAuthFailed)
	}
	if match := bindFailure.FindStringSubmatch(log); match != nil {
		return fmt.Errorf("local port %s is already in use", match[1])
	}
	var last string
	for _, line := range strings.Split(log, "\n") {
		line = system.SanitizeForTerminal(strings.TrimSpace(line))
		if line == "" {
			continue
		}
		for _, marker := range unreachable {
			if strings.Contains(line, marker) {
				return fmt.Errorf("cannot reach %s: %s", host, line)
			}
		}
		last = line
	}
	if last != "" {
		return fmt.Errorf("ssh to %s failed: %s", host, last)
	}
	return fmt.Errorf("ssh to %s failed: %w", host, execErr)
}

// tunnelID turns a tunnel name into a safe file name, hashing long names.
func tunnelID(name string) string {
	id := strings.Map(func(r rune) rune {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '.' || r == '-' || r == '_' {
			return r
		}
		return '_'
	}, name)
	if len(id) <= maxIDLen {
		return id
	}
	sum := sha256.Sum256([]byte(name))
	return id[:maxIDLen-9] + "-" + hex.EncodeToString(sum[:])[:8]
}

func (m *Manager) path(id, ext string) string {
	return filepath.Join(m.dir, id+ext)
}

// states reads every tunnel's state file, keyed by id. A missing directory
// means no tunnels; unreadable state files are skipped.
func (m *Manager) states() (map[string]state, error) {
	entries, err := os.ReadDir(m.dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("reading tunnel directory: %w", err)
	}
	states := map[string]state{}
	for _, e := range entries {
		id, isState := strings.CutSuffix(e.Name(), ".json")
		if !isState {
			continue
		}
		st, err := m.readState(id)
		if err != nil {
			m.logger.Warn("Skipping unreadable tunnel state", "file", e.Name(), "error", err)
			continue
		}
		states[id] = st
	}
	return states, nil
}

func (m *Manager) readState(id string) (state, error) {
	var st state
	data, err := os.ReadFile(m.path(id, ".json"))
	if err != nil {
		return st, err
	}
	err = json.Unmarshal(data, &st)
	return st, err
}

func (m *Manager) writeState(id string, st state) error {
	data, err := json.Marshal(st)
	if err != nil {
		return fmt.Errorf("encoding tunnel state: %w", err)
	}
	if err := os.WriteFile(m.path(id, ".json"), data, 0600); err != nil {
		return fmt.Errorf("saving tunnel state: %w", err)
	}
	return nil
}

func (m *Manager) removeFiles(id string) {
	for _, ext := range []string{".json", ".sock", ".log"} {
		if err := os.Remove(m.path(id, ext)); err != nil && !errors.Is(err, os.ErrNotExist) {
			m.logger.Debug("Failed to remove tunnel file", "file", m.path(id, ext), "error", err)
		}
	}
}
