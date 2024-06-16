package cmd

import (
	"os"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "Milkyway",
	Short: "A brief description of your application",
	Long: `A longer description that spans multiple lines and likely contains
examples and usage of using your application. For example:

Cobra is a CLI library for Go that empowers applications.
This application is a tool to generate the needed files
to quickly create a Cobra application.`,
}

func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func init() {

	rootCmd.CompletionOptions.DisableDefaultCmd = true
	rootCmd.PersistentFlags().IntP("threads", "t", 10, "Number of concurrent threads")
	rootCmd.PersistentFlags().StringP("output", "o", "", "Output file to write results to (defaults to result.xlsx)")
	rootCmd.PersistentFlags().StringP("proxy", "p", "", "HTTP proxy to use for requests")
	rootCmd.PersistentFlags().StringP("url", "u", "", "Scan for target")
	rootCmd.PersistentFlags().StringP("file", "f", "", "Scan for target local file")
}
