package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

// vulnCmd represents the vuln command
var vulnCmd = &cobra.Command{
	Use:   "vuln",
	Short: "A brief description of your command",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("vuln called")
	},
}

func init() {
	rootCmd.AddCommand(vulnCmd)
}
