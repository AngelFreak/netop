package main

import (
	"errors"
	"fmt"
	"os"
	"os/user"
	"sort"
	"strconv"
	"strings"
	"syscall"

	"github.com/angelfreak/net/pkg/tunnel"
	"github.com/angelfreak/net/pkg/types"
	"github.com/spf13/cobra"
)

var tunnelCmd = &cobra.Command{
	Use:   "tunnel [name | host port... | stop [name|port]]",
	Short: "SSH port forwards: list, start or stop",
	Long: `Forward local ports to a remote machine over SSH.

Tunnels run as you, with your SSH keys and ~/.ssh/config; no root needed.
Ports bind to localhost only. A tunnel that drops shows as down; run the
same command again to bring it back.

Ports:
  3000                   localhost:3000 → port 3000 on the SSH host
  13000:3000             localhost:13000 → port 3000 on the SSH host
  5432:db.internal:5432  localhost:5432 → db.internal:5432, reached from the SSH host

A busy local port moves to port+10000 (3000 → 13000), then to any free
port, unless you chose the local port yourself.

Examples:
  net tunnel                         List tunnels
  net tunnel user@100.72.140.241 3000
                                     Forward localhost:3000 to the host's port 3000
  net tunnel app                     Start tunnel "app" from config
  net tunnel stop 3000               Stop the tunnel using local port 3000
  net tunnel stop                    Stop all tunnels`,
	Args: cobra.ArbitraryArgs,
	Run: func(cmd *cobra.Command, args []string) {
		dropped, err := dropSudoPrivileges()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(exitFailed)
		}
		app := createApp()
		app.TunnelSudo = dropped
		if err := app.RunTunnel(args); err != nil {
			os.Exit(exitCode(err))
		}
	},
}

func init() {
	rootCmd.AddCommand(tunnelCmd)
}

// dropSudoPrivileges makes `sudo net tunnel` run as the user who called
// sudo, as if sudo had not been used: tunnels need that user's ssh keys,
// config and known_hosts, and their files must belong to that user. It
// reports whether it dropped.
func dropSudoPrivileges() (bool, error) {
	uid, viaSudo := tunnel.OwnerUID()
	if !viaSudo {
		return false, nil
	}
	u, err := user.LookupId(strconv.Itoa(uid))
	if err != nil {
		return false, fmt.Errorf("looking up sudo user %d: %w", uid, err)
	}
	gid, err := strconv.Atoi(u.Gid)
	if err != nil {
		return false, fmt.Errorf("sudo user %s has invalid gid %q", u.Username, u.Gid)
	}
	var groups []int
	if ids, err := u.GroupIds(); err == nil {
		for _, id := range ids {
			if g, err := strconv.Atoi(id); err == nil {
				groups = append(groups, g)
			}
		}
	}
	if err := syscall.Setgroups(groups); err != nil {
		return false, fmt.Errorf("dropping to %s: setgroups: %w", u.Username, err)
	}
	if err := syscall.Setgid(gid); err != nil {
		return false, fmt.Errorf("dropping to %s: setgid: %w", u.Username, err)
	}
	if err := syscall.Setuid(uid); err != nil {
		return false, fmt.Errorf("dropping to %s: setuid: %w", u.Username, err)
	}
	os.Setenv("HOME", u.HomeDir)
	os.Setenv("USER", u.Username)
	os.Setenv("LOGNAME", u.Username)
	return true, nil
}

// RunTunnel lists tunnels (no args), stops them ("stop [name|port]"), or
// starts a configured ("<name>") or ad-hoc ("<host> <port>...") tunnel.
func (a *App) RunTunnel(args []string) error {
	if len(args) == 0 {
		return a.listTunnels()
	}
	if a.JSON {
		return a.fail("tunnel", errJSONUnsupported("tunnel "+args[0]))
	}
	if args[0] == "stop" {
		if len(args) > 2 {
			return a.tunnelUsage(errors.New("usage: net tunnel stop [name|port]"))
		}
		target := ""
		if len(args) == 2 {
			target = args[1]
		}
		return a.stopTunnels(target)
	}

	spec, err := a.tunnelSpec(args)
	if err != nil {
		return a.tunnelUsage(err)
	}
	st, err := a.TunnelMgr.Start(spec)
	if err != nil {
		a.errorf("Error: %v\n", err)
		if a.TunnelSudo && errors.Is(err, tunnel.ErrAuthFailed) {
			a.errorf("Note: sudo hides your ssh-agent from ssh; run 'net tunnel' without sudo.\n")
		}
		return err
	}
	a.printTunnelStarted(spec, st)
	return nil
}

func (a *App) tunnelUsage(err error) error {
	a.errorf("Error: %v\n", err)
	return withCode(codeUsage, err)
}

// tunnelSpec builds the tunnel to start. A first argument naming a
// configured tunnel starts that; anything else is an ssh host followed by
// the ports to forward.
func (a *App) tunnelSpec(args []string) (types.TunnelSpec, error) {
	name := strings.ToLower(args[0]) // viper lowercases config keys
	if cfg, ok := a.tunnelConfigs()[name]; ok {
		if len(args) > 1 {
			return types.TunnelSpec{}, fmt.Errorf("%q is a configured tunnel, its ports come from the config; start it with: net tunnel %s", args[0], args[0])
		}
		forwards, err := parseForwards(cfg.Forward)
		if err != nil {
			return types.TunnelSpec{}, err
		}
		return types.TunnelSpec{Name: name, Host: cfg.Host, Port: cfg.Port, Identity: cfg.Identity, Forwards: forwards}, nil
	}
	if len(args) == 1 {
		return types.TunnelSpec{}, fmt.Errorf("no tunnel named %q; to forward a port: net tunnel %s 3000", args[0], args[0])
	}

	host := args[0]
	if err := types.ValidateSSHHost(host); err != nil {
		return types.TunnelSpec{}, err
	}
	forwards, err := parseForwards(args[1:])
	if err != nil {
		return types.TunnelSpec{}, err
	}
	return types.TunnelSpec{Name: tunnel.AdHocName(host, forwards), Host: host, Forwards: forwards, AdHoc: true}, nil
}

func parseForwards(specs []string) ([]types.Forward, error) {
	forwards := make([]types.Forward, 0, len(specs))
	for _, s := range specs {
		f, err := types.ParseForward(s)
		if err != nil {
			return nil, err
		}
		forwards = append(forwards, f)
	}
	return forwards, nil
}

func (a *App) tunnelConfigs() map[string]types.TunnelConfig {
	if a.ConfigMgr == nil {
		return nil
	}
	if cfg := a.ConfigMgr.GetConfig(); cfg != nil {
		return cfg.Tunnel
	}
	return nil
}

func (a *App) printTunnelStarted(spec types.TunnelSpec, st *types.TunnelStatus) {
	a.printf("✓ Tunnel %s up via %s\n", st.Name, st.Host)
	for i, f := range st.Forwards {
		note := ""
		if i < len(spec.Forwards) && spec.Forwards[i].LocalPort != f.LocalPort {
			note = fmt.Sprintf(" (%d was in use)", spec.Forwards[i].LocalPort)
		}
		a.printf("  %s%s\n", f, note)
	}
	stopBy := st.Name
	if st.AdHoc && len(st.Forwards) == 1 {
		stopBy = strconv.Itoa(st.Forwards[0].LocalPort)
	}
	a.printf("Stop with: net tunnel stop %s\n", stopBy)
	for _, w := range st.Warnings {
		a.errorf("Warning: %s\n", w)
	}
}

// listTunnels shows tracked tunnels plus configured ones that are not
// running.
func (a *App) listTunnels() error {
	tracked, err := a.TunnelMgr.List()
	if err != nil {
		if !a.JSON {
			a.errorf("Error: %v\n", err)
		}
		return a.fail("tunnel", err)
	}
	entries := tunnelEntries(tracked)
	for name, cfg := range a.tunnelConfigs() {
		if hasTunnelNamed(entries, name) {
			continue
		}
		forwards, _ := parseForwards(cfg.Forward) // validated when the config loaded
		if forwards == nil {
			forwards = []types.Forward{}
		}
		entries = append(entries, tunnelEntry{Name: name, Host: cfg.Host, State: tunnelStopped, Forwards: forwards})
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name < entries[j].Name })

	if a.JSON {
		return a.emit("tunnel", tunnelListResult{Tunnels: entries})
	}
	if len(entries) == 0 {
		a.println("No tunnels")
		return nil
	}
	for _, e := range entries {
		a.println(tunnelLine(e))
	}
	return nil
}

func hasTunnelNamed(entries []tunnelEntry, name string) bool {
	for _, e := range entries {
		if strings.EqualFold(e.Name, name) {
			return true
		}
	}
	return false
}

// tunnelLine renders one tunnel, e.g.
// "app (user@box) - up: localhost:13000 → 127.0.0.1:3000".
func tunnelLine(e tunnelEntry) string {
	forwards := make([]string, len(e.Forwards))
	for i, f := range e.Forwards {
		forwards[i] = f.String()
	}
	return fmt.Sprintf("%s (%s) - %s: %s", e.Name, e.Host, e.State, strings.Join(forwards, ", "))
}

func (a *App) stopTunnels(target string) error {
	stopped, err := a.TunnelMgr.Stop(target)
	if err != nil {
		a.errorf("Error: %v\n", err)
		return err
	}
	if len(stopped) == 0 {
		a.println("No tunnels running")
		return nil
	}
	for _, st := range stopped {
		a.printf("✓ Tunnel %s stopped\n", st.Name)
	}
	return nil
}
