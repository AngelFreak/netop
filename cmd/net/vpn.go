package main

import (
	"os"

	"github.com/spf13/cobra"
)

var vpnCmd = &cobra.Command{
	Use:   "vpn [name|stop]",
	Short: "List VPNs, connect, or disconnect",
	Long: `Manage VPN connections (OpenVPN and WireGuard).

Without arguments: Lists all configured VPNs and their status.
With name: Connects to the specified VPN from config.
With "stop": Disconnects all VPNs.

Examples:
  net vpn                 List all VPNs (configured and running)
  net vpn work            Connect to VPN "work"
  net vpn stop            Disconnect all VPNs`,
	Run: func(cmd *cobra.Command, args []string) {
		arg := ""
		if len(args) > 0 {
			arg = args[0]
		}
		if err := createApp().RunVPN(arg); err != nil {
			os.Exit(exitCode(err))
		}
	},
}

var genkeyCmd = &cobra.Command{
	Use:   "genkey",
	Short: "Generate a WireGuard private/public key pair",
	Run: func(cmd *cobra.Command, args []string) {
		if err := createApp().RunGenkey(); err != nil {
			os.Exit(exitCode(err))
		}
	},
}

func init() {
	rootCmd.AddCommand(vpnCmd)
	rootCmd.AddCommand(genkeyCmd)
}
