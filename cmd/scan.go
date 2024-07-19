package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

// scanCmd represents the scan command
var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "A brief description of your command",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("scan called")
	},
}

func init() {
	rootCmd.AddCommand(scanCmd)
}
