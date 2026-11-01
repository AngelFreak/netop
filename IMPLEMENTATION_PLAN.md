# Apply WireGuard MTU and DNS instead of ignoring them

A WireGuard `config:` block accepts `MTU` and `DNS` under `[Interface]`, but
netop silently discards both: `applyInterfaceKey` (pkg/wgconfig/parse.go) lists
them as "handled by the caller", and no caller ever handled them. Result: a
tunnel needing `MTU = 1380` comes up at 1420 (fragmentation hangs), and
`DNS = 10.77.0.1` never reaches resolv.conf, so split-tunnel internal names
don't resolve.

Decisions: values are parsed from the inline `[Interface]` block (no new YAML
keys, so existing configs start working as written). VPN DNS is restored to the
pre-VPN state on disconnect.

## Stage 1: Extract MTU and DNS from the config block
**Goal**: `wgconfig` exposes the two wg-quick keys it currently drops, without
changing what reaches the kernel device.
**Success Criteria**: A parsed Skoven-style config reports MTU 1380 and DNS
[10.77.0.1, orisonnet]; `wgtypes.Config` is byte-identical to today's output.
**Tests**:
- MTU/DNS absent → zero value, no error (existing configs unaffected)
- `MTU = 1380` → 1380; `MTU = 0`/`-1`/`68`/`70000`/`abc` → error
- `DNS = 10.77.0.1, orisonnet` → both entries preserved in order
- existing parse_test.go cases still pass unchanged
**Status**: Complete

## Stage 2: Apply MTU to the link
**Goal**: `LinkManager` can set an interface MTU, and connectWireGuard does.
**Success Criteria**: Connecting Skoven leaves wg0 at MTU 1380.
**Tests**:
- fake LinkManager records SetMTU(iface, 1380)
- MTU applied before SetUp, after AddWireGuard
- MTU 0 (unset) → SetMTU never called (byte-identical to baseline)
- SetMTU failure → interface cleaned up, error returned (matches sibling paths)
- netlink integration test (root/netns): real wg link reports 1380
**Status**: Not Started

## Stage 3: Apply VPN DNS, restore on disconnect
**Goal**: WireGuard DNS reaches resolv.conf and is undone on disconnect.
**Success Criteria**: Skoven connect → resolv.conf has `nameserver 10.77.0.1`;
disconnect → the network's prior DNS is back.
**Tests**:
- connect with DNS → SetDNS called with parsed servers
- non-IP entry (`orisonnet`) → skipped with a warning, valid servers still applied
- no DNS key → SetDNS never called (byte-identical to baseline)
- prior DNS persisted in the state file and reapplied on disconnect
- state file with 6 fields (pre-upgrade) still loads (backward compat)
- DNS failure is non-fatal: tunnel stays up, warning logged
**Status**: Not Started

## Stage 4: Wire through the real CLI path and document
**Goal**: Prove it works on the production path, not just in unit tests.
**Success Criteria**: An integration test drives `net vpn <name>` wiring end to
end and fails if MTU/DNS is disconnected; config.example and README document
both keys as supported.
**Tests**:
- integration test through the app's real VPN manager construction
- `go test ./...` green; `go vet` clean
**Status**: Not Started
