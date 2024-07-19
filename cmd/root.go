package cmd

import (
	"context"
	"fmt"
	"github.com/polite007/Milkyway/module/httpcreate"
	"os"
	"os/signal"

	"github.com/spf13/cobra"
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

func parseGlobalOptions() (*httpcreate.Options, error) {
	globalOpts := httpcreate.NewOptions()
	threads, err := rootCmd.Flags().GetInt("threads")
	if err != nil {
		return nil, fmt.Errorf("invalid value for threads: %w", err)
	}

	if threads <= 0 {
		return nil, fmt.Errorf("threads must be bigger than 0")
	}
	globalOpts.Threads = threads

	target, err := rootCmd.Flags().GetString("url")
	if err != nil {
		return nil, fmt.Errorf("invalid value for url: %w", err)
	}
	globalOpts.Url = target

	output, err := rootCmd.Flags().GetString("output")
	if err != nil {
		return nil, fmt.Errorf("invalid value for output: %w", err)
	}
	globalOpts.Output = output

	Proxy, err := rootCmd.Flags().GetString("proxy")
	if err != nil {
		return nil, fmt.Errorf("invalid value for proxy: %w", err)
	}
	globalOpts.Proxy = Proxy

	file, err := rootCmd.Flags().GetString("file")
	if err != nil {
		return nil, fmt.Errorf("invalid value for file: %w", err)
	}
	globalOpts.File = file

	return globalOpts, nil
}

func init() {
	rootCmd.CompletionOptions.DisableDefaultCmd = true
	rootCmd.PersistentFlags().IntP("threads", "t", 10, "Number of concurrent threads")
	rootCmd.PersistentFlags().StringP("output", "o", "", "Output file to write results to (defaults to result.xlsx)")
	rootCmd.PersistentFlags().StringP("proxy", "p", "", "HTTP proxy to use for requests")
	rootCmd.PersistentFlags().StringP("url", "u", "", "Scan for target")
	rootCmd.PersistentFlags().StringP("file", "f", "", "Scan for target local file")
}
