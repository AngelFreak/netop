# SSH Tunnels Design

**Status:** Approved 2026-10-13

## Goal

Let `net` manage SSH port forwards, both ad hoc and from config, so that

```
ssh -N -L 13000:127.0.0.1:3000 user@100.72.140.241
```

becomes `net tunnel 100.72.140.241 3000`: shorter, tracked, listed and
stoppable by name or port. Ad-hoc use must be easier than plain ssh, not just
a wrapper around the same syntax.

## Scope

- **In:** local forwards (`-L`) to a remote-side host:port, several per tunnel.
- **Out (YAGNI):** dynamic SOCKS (`-D`), remote forwards (`-R`), full-tunnel
  over SSH (`-w`/sshuttle), auto-reconnect. A dropped tunnel shows as down;
  re-running the command brings it back.

## Command surface

```
net tunnel                          list configured + running tunnels (--json supported)
net tunnel <name>                   start configured tunnel <name>
net tunnel <host> <fwd>...          start an ad-hoc tunnel
net tunnel stop [<name>|<port>]     stop one tunnel (by name or local port), or all
```

The first argument is a configured name if it matches a key under `tunnel:`
(case-insensitive, as viper lowercases keys). Otherwise it is a host and at
least one forward is required. `net tunnel foo` with no forwards and no config
entry fails: `no tunnel named "foo"; to forward a port: net tunnel foo 3000`.

### Forward shorthand

| Form | Meaning |
|---|---|
| `3000` | local 3000 → remote `127.0.0.1:3000` |
| `13000:3000` | local 13000 → remote `127.0.0.1:3000` (local port pinned) |
| `5432:db.internal:5432` | local 5432 → `db.internal:5432` as seen from the SSH host (pinned) |

Forwards always bind `127.0.0.1` locally, never all interfaces.

### Busy local port

For the bare `3000` form only: if local 3000 is taken, try 13000 (port +
10000, the user's own convention), then any free port. The chosen port is
printed. A pinned local port that is busy is an error.

### Host

Anything ssh accepts: `user@ip`, a `~/.ssh/config` alias, a MagicDNS name.
ssh runs as the invoking user, so their `User`, `Port`, `IdentityFile` and
`known_hosts` apply. A host starting with `-` is rejected and the host is
passed after `--`, so it can never be read as an ssh option.

### Output

```
$ net tunnel 100.72.140.241 3000
✓ Tunnel 100.72.140.241:3000 up via 100.72.140.241
  localhost:3000 → 127.0.0.1:3000
Stop with: net tunnel stop 3000
```

A forward that moved off a busy port gets ` (3000 was in use)` after it.

Ad-hoc tunnels are named `<host>:<remote ports joined by ,>`. Starting a
tunnel that is already up is a no-op that reports it as up.

## Config

```yaml
tunnel:
  app:
    host: user@100.72.140.241
    forward:
      - 13000:3000
    port: 22                      # optional, ssh -p
    identity: ~/.ssh/id_ed25519   # optional, ssh -i
```

`tunnel` becomes a reserved top-level key (not a network). Validation runs on
the raw map, because viper's weak typing would otherwise coerce mistakes.
Checks: known fields only, `host` is a non-empty string, `port` is in 1–65535,
and `forward` is a non-empty list of valid forward specs. Ints are allowed,
since YAML reads `- 3000` as a number.

## Architecture

- `pkg/types`: `TunnelSpec`, `Forward`, `TunnelStatus`, `TunnelManager`
  interface, `ParseForward` (shared by config validation and the CLI), and
  `TunnelConfig` under `Config.Tunnel`.
- `pkg/tunnel`: `Manager` implementing `Start`, `Stop` and `List`.
- `cmd/net/tunnel.go`: the cobra command. `App.RunTunnel` holds the logic and
  merges configured-but-down tunnels from config into the list, so the manager
  stays config-agnostic.

### Launching ssh

One ssh master process per tunnel:

```
ssh -f -N -M -S <id>.sock -E <id>.log
    -o BatchMode=yes -o ExitOnForwardFailure=yes
    -o ServerAliveInterval=15 -o ServerAliveCountMax=3 -o ControlPersist=no
    [-p port] [-i identity]
    -L 127.0.0.1:<l>:<host>:<r> ...  -- <host>
```

All of these were verified against OpenSSH 9.6 on 2026-10-13:

- `-f` with `ExitOnForwardFailure` returns, after about 50 ms, only once the
  forwards are bound. Failures exit 255.
- `ssh -S sock -O check <host>` prints `Master running (pid=N)`, and
  `-O exit` stops the master. The control socket replaces PID files.
- With `-E`, every error goes to the log file and stderr stays empty.
- Connecting to a forward whose remote port is closed: the local connect
  succeeds, the read gets EOF at once, and the log says
  `channel N: open failed: connect failed: ...`.

### State

Per tunnel: `<id>.json` (name, host, forwards, ad-hoc flag, start time),
`<id>.sock` and `<id>.log` in the tunnel directory. `<id>` is the name with
characters outside `[A-Za-z0-9._-]` replaced by `_`, plus a short hash suffix
if it is long. The cap keeps socket paths under the 108-byte `sun_path` limit.

Tunnel directory, for the owning uid:
1. `$XDG_RUNTIME_DIR/net/tunnels`, when running as that uid and it is set
2. `/run/user/<uid>/net/tunnels`, when `/run/user/<uid>` exists
3. `/tmp/net-<uid>/tunnels`

The directory is created 0700 and must be a real directory (not a symlink)
owned by the uid with no group or other access. Anything else is an error.

`List` reads the state files and runs `-O check` on each. A tunnel whose check
fails is reported down. `Stop` and a fresh `Start` clean up its files.

### Privileges

- `tunnel` joins the root-exempt commands, so normal use never runs sudo.
- When run as root with `SUDO_UID` set (for example `alias net='sudo net'`),
  `net tunnel` drops the whole process to `SUDO_UID`/`SUDO_GID` before doing
  anything and sets `HOME`/`USER`/`LOGNAME` from the passwd entry. All files
  and the ssh process then belong to the user. sudo strips `SSH_AUTH_SOCK`, so
  keys that only live in the agent won't work this way; the auth error says so.
- `net stop` does not touch tunnels: they belong to the user, not to the
  network stack.

## Errors

ssh's log is turned into actionable messages:

| ssh says | net says |
|---|---|
| `Host key verification failed` | host key for X is not trusted yet; run `ssh X` once to check and accept it |
| `Permission denied` | X refused the login; tunnels need key or agent auth, not a password (test with `ssh X`) |
| `Address already in use` | local port N is already in use |
| `Could not resolve hostname`, `Connection refused`, `timed out`, `No route to host` | cannot reach X: the ssh line |
| anything else | the last log line |

**Remote port probe.** After start, net connects once to each forward. If the
log then gains `open failed`, it warns: `connected, but nothing is listening
on 127.0.0.1:3000 on <host>`. The tunnel stays up, since the remote service
may start later.

**Dropped from the brainstorm:** naming the process that holds a busy port.
That needs `/proc` fd scanning, and the auto-fallback already covers the
common case.

## `net status` and `--json`

- `net status` prints a `Tunnels:` line only when at least one tunnel exists,
  so its output stays byte-identical otherwise (golden test).
- The status JSON gains `tunnels` with `omitempty`.
- `net tunnel` (list) supports `--json`. Start and stop reject `--json` like
  the other mutating commands until stage 2 of the JSON work.

## Testing

- **Unit:** forward parsing, port fallback with an injected
  "is this port free?" check, exact ssh argv, log-to-error classification,
  tunnel-dir safety checks, config validation, root exemption.
- **End-to-end with real ssh:** an in-process SSH server built on
  `golang.org/x/crypto/ssh` (already a dependency) that serves `direct-tcpip`
  only. Tests drive the real `ssh` client through `Manager` and through
  `App.RunTunnel`: start, then HTTP through the tunnel, list, the closed-port
  warning, the busy-port fallback, the unknown-host-key and auth errors, and
  stop. It needs no root or sshd, so it runs in normal `go test` and skips if
  `ssh` is missing.
- **Golden:** `net status` text is unchanged when there are no tunnels.
