package cmd

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"time"

	"github.com/polite007/Milkyway/config"
	"github.com/polite007/Milkyway/internal/cli"
	"github.com/polite007/Milkyway/internal/service/task"
	"github.com/polite007/Milkyway/pkg/logger"
	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:          config.Name,
	Short:        config.Logo,
	SilenceUsage: true,
	RunE:         RunRoot,
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
			cancel()
			os.Exit(1)
		case <-mainContext.Done():
		}
	}()
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func RunRoot(cmd *cobra.Command, args []string) error {
	var (
		ipList    []string     // ip列表
		urlList   []string     // url列表
		timeStart = time.Now() // 任务开始时间
		err       error
	)
	if err = cli.ParseArgs(cmd); err != nil {
		return err
	}
	config.Get().PrintDefaultUsage()
	ipList, urlList, err = cli.ParseTarget()
	if err != nil {
		return err
	}
	if len(ipList) != 0 {
		if config.Get().Vul.IpActiveList, err = task.IpActiveScan(ipList); err != nil {
			return err
		}
		if config.Get().Vul.IpPortList, err = task.PortActiveScan(config.Get().Vul.IpActiveList, cli.ParsePort(config.Get().Port)); err != nil {
			return err
		}
		if config.Get().Vul.IpPortList, config.Get().Vul.WebList, err = task.WebActiveScan(config.Get().Vul.IpPortList); err != nil {
			return err
		}
	}
	if len(urlList) != 0 {
		if WebListOne, err := task.WebScanWithDomain(urlList); err == nil {
			config.Get().Vul.WebList = append(config.Get().Vul.WebList, WebListOne...)
		}
	}
	if err = task.ProtocolVulScan(config.Get().Vul.IpPortList); err != nil {
		return err
	}
	if err = task.WebPocVulScan(config.Get().Vul.WebList); err != nil {
		return err
	}
	// 等待所有日志写入
	logger.LogWaitGroup.Wait()
	logger.OutLog(fmt.Sprintf("ScanTime: %s\n", time.Since(timeStart).String()))
	// 开始报告输出
	config.Get().Report = true // 暂时写死为true
	if config.Get().Report {
		config.Get().Vul.GenerateReport()
	}
	return nil
}

func init() {
	rootCmd.Flags().BoolP("scan-random", "r", false, "Randomize the order of ports scan")
	rootCmd.Flags().StringP("finger-file", "w", "", "Path to the file containing fingerprint rules")
	rootCmd.Flags().IntP("fofa-size", "z", 100, "Maximum number of results to retrieve from Fofa")
	rootCmd.Flags().StringP("poc-id", "i", "", "POC ID to scan for")
	rootCmd.Flags().StringP("poc-tags", "g", "", "Comma-separated list of POC tags to scan for")
	rootCmd.Flags().StringP("poc-file", "e", "", "Path to the file containing custom POCs (File Or Dir)")
	rootCmd.Flags().BoolP("no-match", "m", false, "Fingerprint rule matching prior to vulnerability scanning")
	rootCmd.Flags().BoolP("no-ping", "n", false, "Skip the ICMP ping step")
	rootCmd.Flags().BoolP("full-scan", "l", false, "Fully detect protocols on open ports.By default,only common ones like 22-SSH and 3306-MySQL are identified.")
	rootCmd.Flags().BoolP("verbose", "v", false, "Print detailed protocol information during scanning")
	rootCmd.Flags().StringP("url", "u", "", "URL of the target to scan")
	rootCmd.Flags().StringP("socks5", "s", "", "SOCKS5 proxy")
	rootCmd.Flags().StringP("file", "f", "", "File path for target address")
	rootCmd.Flags().IntP("concurrent", "c", 500, "Number of concurrent threads for scanning")
	rootCmd.Flags().StringP("http-proxy", "y", "", "HTTP proxy")
	rootCmd.Flags().StringP("target", "t", "", "Target addresses to scan")
	rootCmd.Flags().StringP("port", "p", "default", "Target port(s) to scan")
	rootCmd.Flags().StringP("output", "o", "output.txt", "Output file path")
	rootCmd.Flags().StringP("fofa-key", "k", "", "FOFA API key")
	rootCmd.Flags().StringP("fofa-query", "q", "", "Path to the file containing FOFA queries.The queries in the file will be read and executed")
}
