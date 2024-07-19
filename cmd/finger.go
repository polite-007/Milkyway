package cmd

import (
	"github.com/spf13/cobra"
)

var fingerCmd *cobra.Command

func runFinger(cmd *cobra.Command, args []string) error {
	//globalopts, pluginopts, err := parseDirOptions()

	return nil
}

func init() {
	fingerCmd = &cobra.Command{
		Use:   "dir",
		Short: "Uses directory/file enumeration mode",
		RunE:  runFinger,
	}
	rootCmd.AddCommand(fingerCmd)
}
