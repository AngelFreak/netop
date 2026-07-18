package main

import (
	"os"

	"github.com/spf13/cobra"
)

var statusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show full network status (connection, internet/captive portal, VPN, hotspot, DHCP)",
	Run: func(cmd *cobra.Command, args []string) {
		if err := createApp().RunStatus(); err != nil {
			os.Exit(1)
		}
	},
}

var showCmd = &cobra.Command{
	Use:   "show [network]",
	Short: "Show config file settings (all networks or specific one)",
	Long: `Display configuration from ~/.net/config.yaml.

Without arguments: Shows common settings, all networks, VPNs, and ignored interfaces.
With network name: Shows detailed config for that specific network.

Examples:
  net show                Show all configuration
  net show home           Show config for network "home"`,
	Run: func(cmd *cobra.Command, args []string) {
		networkName := ""
		if len(args) > 0 {
			networkName = args[0]
		}
		if err := createApp().RunShow(networkName); err != nil {
			os.Exit(1)
		}
	},
}

func init() {
	rootCmd.AddCommand(statusCmd)
	rootCmd.AddCommand(showCmd)
}
