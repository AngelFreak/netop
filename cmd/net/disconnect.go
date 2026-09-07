package main

import (
	"os"

	"github.com/spf13/cobra"
)

var stopCmd = &cobra.Command{
	Use:   "stop [interface...]",
	Short: "Disconnect everything (network, VPN, hotspot, DHCP) or specific interfaces",
	Long: `Stop all network services or bring down specific interfaces.

Without arguments: Stops network (WiFi/wired), VPN, hotspot, DHCP server, and clears DNS.
With arguments: Brings down only the specified interfaces.

Examples:
  net stop              Disconnect everything
  net stop wlan0        Bring down wlan0 only
  net stop eth0 wlan0   Bring down multiple interfaces`,
	Run: func(cmd *cobra.Command, args []string) {
		rejectJSON("stop")
		if err := createApp().RunStop(args); err != nil {
			os.Exit(1)
		}
	},
}

func init() {
	rootCmd.AddCommand(stopCmd)
}
