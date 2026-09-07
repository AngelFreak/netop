package main

import (
	"os"

	"github.com/spf13/cobra"
)

var macCmd = &cobra.Command{
	Use:   "mac [address]",
	Short: "Set MAC address (random, or specific like AA:BB:CC:DD:EE:FF)",
	Long: `Change the MAC address of the network interface.

Without arguments: Generates a random MAC address.
With argument: Sets the specified MAC address.

Examples:
  net mac                         Random MAC
  net mac random                  Random MAC (explicit)
  net mac AA:BB:CC:DD:EE:FF       Set specific MAC
  net mac default                 Randomize with Apple OUI prefix`,
	Run: func(cmd *cobra.Command, args []string) {
		rejectJSON("mac")
		mac := ""
		if len(args) > 0 {
			mac = args[0]
		}
		if err := createApp().RunMAC(mac); err != nil {
			os.Exit(1)
		}
	},
}

func init() {
	rootCmd.AddCommand(macCmd)
}
