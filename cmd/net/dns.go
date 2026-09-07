package main

import (
	"os"

	"github.com/spf13/cobra"
)

var dnsCmd = &cobra.Command{
	Use:   "dns [server...]",
	Short: "Set DNS servers (or 'dns dhcp' to restore DHCP DNS)",
	Long: `Set custom DNS servers or restore DHCP-provided DNS.

Examples:
  net dns 1.1.1.1              Use Cloudflare DNS
  net dns 8.8.8.8 8.8.4.4      Use Google DNS
  net dns 1.1.1.1 9.9.9.9      Cloudflare + Quad9
  net dns dhcp                 Restore DHCP-provided DNS`,
	Run: func(cmd *cobra.Command, args []string) {
		rejectJSON("dns")
		if err := createApp().RunDNS(args); err != nil {
			os.Exit(1)
		}
	},
}

func init() {
	rootCmd.AddCommand(dnsCmd)
}
