package cmd

import (
	"context"
	"fmt"
	"github.com/polite007/Milkyway/config"
	"github.com/polite007/Milkyway/internal/cli"
	"github.com/polite007/Milkyway/internal/service/task"
	"github.com/polite007/Milkyway/internal/utils/httpx"
	"github.com/polite007/Milkyway/pkg/logger"
	"github.com/spf13/cobra"
	"os"
	"os/signal"
	"time"
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
		ipList  []string // ip列表
		urlList []string // url列表

		IpActiveList []string                          // 存活ip列表
		IpPortList   map[string][]*config.PortProtocol // ip:port:protocol
		WebListOne   []*httpx.Resps
		WebListTwo   []*httpx.Resps
		WebList      []*httpx.Resps
		err          error
	)
	// 解析参数
	if err = cli.ParseArgs(cmd); err != nil {
		return err
	}
	// 获取ip列表和url列表
	ipList, urlList, err = cli.ParseTarget()
	if err != nil {
		return err
	}
	// 打印默认信息
	config.Get().PrintDefaultUsage()
	// 开始探测&识别任务
	// 根据ip探测
	timeNow := time.Now()
	if len(ipList) != 0 {
		IpActiveList, err = task.IpActiveScan(ipList) // 探测存活IP&端口&端口协议识别
		if err != nil {
			return err
		}
		IpPortList, err = task.PortActiveScan(IpActiveList)
		if err != nil {
			return err
		}
		IpPortList, WebListOne, err = task.WebActiveScan(IpPortList) // 探测Web服务&返回有协议的ip/port列表
		if err != nil {
			return err
		}
	}
	// 根据url探测
	if len(urlList) != 0 {
		WebListTwo, err = task.WebScanWithDomain(urlList)
		if err != nil {
			return err
		}
	}

	// 开启漏洞扫描
	// 协议漏洞扫描
	if err = task.ProtocolVulScan(IpPortList); err != nil {
		return err
	}
	// web漏洞扫描
	WebList = append(WebListTwo, WebListOne...)
	if err = task.WebPocVulScan(WebList); err != nil {
		return err
	}
	// 等待所有日志写入
	logger.LogWaitGroup.Wait()
	fmt.Printf("ScanTime: %s\n", time.Since(timeNow).String())
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
