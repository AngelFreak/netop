package main

import (
	"os"

	"github.com/angelfreak/net/pkg/types"
	"github.com/spf13/cobra"
)

var hotspotCmd = &cobra.Command{
	Use:   "hotspot [start|stop|status]",
	Short: "Create a WiFi hotspot to share your connection",
	Long: `Create and manage a WiFi access point.

Without arguments: Shows hotspot status.

Features:
  - Supports 2.4GHz (channels 1-14) and 5GHz (channels 36-165)
  - Automatic NAT/IP forwarding for internet sharing
  - WPA2 encryption with password protection

Examples:
  net hotspot                           Show status
  net hotspot start                     Start with defaults (SSID: net-hotspot)
  net hotspot start --ssid MyHotspot    Start with custom SSID
  net hotspot start --password secret   Start with WPA2 password
  net hotspot start --channel 36        Start on 5GHz channel 36
  net hotspot stop                      Stop the hotspot`,
	Run: func(cmd *cobra.Command, args []string) {
		rejectJSON("hotspot")
		action := "status"
		if len(args) > 0 {
			action = args[0]
		}

		var config *types.HotspotConfig
		if action == "start" {
			// Get configuration from flags or use defaults
			ssid, _ := cmd.Flags().GetString("ssid")
			password, _ := cmd.Flags().GetString("password")
			channel, _ := cmd.Flags().GetInt("channel")
			gateway, _ := cmd.Flags().GetString("gateway")
			ipRange, _ := cmd.Flags().GetString("ip-range")
			dnsServers, _ := cmd.Flags().GetStringSlice("dns")

			// Set defaults if not provided
			if ssid == "" {
				ssid = "net-hotspot"
			}
			if channel == 0 {
				channel = 6
			}
			if gateway == "" {
				gateway = "192.168.50.1"
			}
			if ipRange == "" {
				ipRange = "192.168.50.50,192.168.50.150"
			}
			if len(dnsServers) == 0 {
				dnsServers = []string{"8.8.8.8", "8.8.4.4"}
			}

			config = &types.HotspotConfig{
				Interface: iface,
				SSID:      ssid,
				Password:  password,
				Channel:   channel,
				Gateway:   gateway,
				IPRange:   ipRange,
				DNS:       dnsServers,
			}
		}

		if err := createApp().RunHotspot(action, config); err != nil {
			os.Exit(1)
		}
	},
}

func init() {
	hotspotCmd.Flags().String("ssid", "", "Hotspot SSID (default: net-hotspot)")
	hotspotCmd.Flags().String("password", "", "Hotspot password (min 8 chars, empty for open network)")
	hotspotCmd.Flags().Int("channel", 6, "WiFi channel (2.4GHz: 1-14, 5GHz: 36,40,44,48,149,153,157,161,165)")
	hotspotCmd.Flags().String("gateway", "192.168.50.1", "Gateway IP address")
	hotspotCmd.Flags().String("ip-range", "192.168.50.50,192.168.50.150", "DHCP IP range")
	hotspotCmd.Flags().StringSlice("dns", []string{"8.8.8.8", "8.8.4.4"}, "DNS servers")

	rootCmd.AddCommand(hotspotCmd)
}
