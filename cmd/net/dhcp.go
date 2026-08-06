package main

import (
	"fmt"
	"os"

	"github.com/angelfreak/net/pkg/types"
	"github.com/spf13/cobra"
)

var dhcpServerCmd = &cobra.Command{
	Use:     "share [start|stop|status]",
	Aliases: []string{"dhcp"},
	Short:   "Share this machine's internet with devices on another interface",
	Long: `Share this machine's internet connection with devices plugged into (or
connected via) another interface.

This turns the chosen interface into a small network that this machine runs:
it assigns the interface an IP, serves addresses to connected devices over
DHCP, and NATs their traffic out through whichever interface currently has
the default route. The classic use is sharing WiFi over an ethernet cable.

This is NOT a DHCP client. To obtain an address for this machine, just
connect normally with "net <name>" or "net connect <ssid>".

The uplink is detected automatically from the default route. If no uplink is
found, the server still starts but sharing is inactive and you are warned;
use --require-nat to make that a hard failure instead.

Examples:
  net share                                            Show status and leases
  net share start --interface eth0                     Share over eth0
  net share start --interface eth0 --require-nat       Fail if sharing can't work
  net share start --interface eth0 --gateway 10.0.0.1  Custom gateway
  net share stop                                       Stop sharing

Still available as "net dhcp".`,
	Run: func(cmd *cobra.Command, args []string) {
		rejectJSON("dhcp")
		action := "status"
		if len(args) > 0 {
			action = args[0]
		}

		var config *types.DHCPServerConfig
		if action == "start" {
			// Interface is required for start
			ifaceName, _ := cmd.Flags().GetString("interface")
			if ifaceName == "" {
				fmt.Fprintln(os.Stderr, "Error: --interface is required — the interface to share OVER,")
				fmt.Fprintln(os.Stderr, "not your uplink (e.g., --interface eth0 to share over ethernet).")
				os.Exit(1)
			}

			// Get configuration from flags or use defaults
			gateway, _ := cmd.Flags().GetString("gateway")
			ipRange, _ := cmd.Flags().GetString("ip-range")
			dnsServers, _ := cmd.Flags().GetStringSlice("dns")
			leaseTime, _ := cmd.Flags().GetString("lease-time")
			requireNAT, _ := cmd.Flags().GetBool("require-nat")

			// Set defaults if not provided
			if gateway == "" {
				gateway = "192.168.100.1"
			}
			if ipRange == "" {
				ipRange = "192.168.100.50,192.168.100.150"
			}
			if len(dnsServers) == 0 {
				dnsServers = []string{"8.8.8.8", "8.8.4.4"}
			}
			if leaseTime == "" {
				leaseTime = "12h"
			}

			config = &types.DHCPServerConfig{
				Interface:  ifaceName,
				Gateway:    gateway,
				IPRange:    ipRange,
				DNS:        dnsServers,
				LeaseTime:  leaseTime,
				RequireNAT: requireNAT,
			}
		}

		if err := createApp().RunDHCPServer(action, config); err != nil {
			os.Exit(1)
		}
	},
}

func init() {
	dhcpServerCmd.Flags().String("interface", "", "Interface to share over — the one devices connect to (required for start)")
	dhcpServerCmd.Flags().String("gateway", "192.168.100.1", "Gateway IP address")
	dhcpServerCmd.Flags().String("ip-range", "192.168.100.50,192.168.100.150", "DHCP IP range")
	dhcpServerCmd.Flags().StringSlice("dns", []string{"8.8.8.8", "8.8.4.4"}, "DNS servers")
	dhcpServerCmd.Flags().String("lease-time", "12h", "DHCP lease time (e.g., 12h, 24h)")
	dhcpServerCmd.Flags().Bool("require-nat", false, "Fail to start if internet sharing cannot be configured")

	rootCmd.AddCommand(dhcpServerCmd)
}
