package main

import (
	"os"

	"github.com/angelfreak/net/pkg/types"
	"github.com/spf13/cobra"
)

var portalCmd = &cobra.Command{
	Use:   "portal",
	Args:  cobra.NoArgs, // scripting command with exit-code semantics — reject stray args
	Short: "Check for a captive portal on the current connection",
	Long: `Probe a connectivity-check URL to determine whether the current network
has working internet or a captive portal intercepting traffic.

A captive portal is reported only on positive evidence (redirect, HTTP 511,
or a rewritten response body). Probe failures and server errors are reported
as "unreachable" — if the probe endpoint itself is down, that is not a portal.

The probe follows normal process routing; on a multi-homed machine it
reflects the preferred interface, not necessarily the one you care about.
Output names the preferred IPv4 default route when known — an IPv4-main-table
metric heuristic, not a guarantee of probe egress. HTTP proxy environment
variables are intentionally ignored
— a proxy would answer on the portal's behalf and mask it.

This command always probes, even with common.portal.check: off (which only
disables the automatic checks in connect and status).

Exit codes: 0 = online, 2 = captive portal detected, 1 = offline,
3 = configuration or internal error.`,
	Run: func(cmd *cobra.Command, args []string) {
		status, err := createApp().RunPortal()
		if err != nil {
			os.Exit(3)
		}
		switch status {
		case types.PortalStatusOnline:
			// exit 0
		case types.PortalStatusPortal:
			os.Exit(2)
		default:
			// Offline, Unknown, future statuses: never exit 0 by accident.
			os.Exit(1)
		}
	},
}

func init() {
	rootCmd.AddCommand(portalCmd)
}
