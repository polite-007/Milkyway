package cmd

import (
	"context"
	"fmt"
	"github.com/spf13/cobra"
	"os"
	"os/signal"
)

var rootCmd = &cobra.Command{
	Use:          "Milkyway",
	Short:        "An innovative vulnerability scanner and Pentest Tool",
	SilenceUsage: true,
}

var mainContext context.Context

func Execute() {
	var cancel context.CancelFunc
	mainContext, cancel = context.WithCancel(context.Background())
	defer cancel()
	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, os.Interrupt)
	defer func() {
		signal.Stop(signalChan)
		cancel()
	}()
	go func() {
		select {
		case <-signalChan:
			// caught CTRL+C
			fmt.Println("\n[!] Keyboard interrupt detected, terminating.")
			cancel()
		case <-mainContext.Done():
		}
	}()
	if err := rootCmd.Execute(); err != nil {
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
