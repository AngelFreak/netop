package main

import (
	"os"

	"github.com/spf13/cobra"
)

var scanCmd = &cobra.Command{
	Use:   "scan [open]",
	Short: "Scan for WiFi networks (use 'scan open' to show only unprotected)",
	Run: func(cmd *cobra.Command, args []string) {
		showOpen := len(args) > 0 && args[0] == "open"
		if err := createApp().RunScan(showOpen); err != nil {
			os.Exit(exitCode(err))
		}
	},
}

func init() {
	rootCmd.AddCommand(scanCmd)
}
