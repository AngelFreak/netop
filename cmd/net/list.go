package main

import (
	"os"

	"github.com/spf13/cobra"
)

var listCmd = &cobra.Command{
	Use:   "list",
	Short: "List active connections with IP, gateway, and DNS info",
	Run: func(cmd *cobra.Command, args []string) {
		if err := createApp().RunList(); err != nil {
			os.Exit(exitCode(err))
		}
	},
}

func init() {
	rootCmd.AddCommand(listCmd)
}
