package config

import (
	"fmt"
	"time"
)

// 私有全局变量
var (
	sC             string
	pocId          string
	pocTags        string
	fingerMatch    bool
	fingerFile     string
	pocFile        string
	noPing         bool
	fullScan       bool
	sshKey         string
	verbose        bool
	FofaQuery      string
	FofaSize       int
	FofaKey        string
	scanRandom     bool
	httpProxy      string
	socks5Proxy    string
	port           string
	target         string
	targetUrl      string
	targetFile     string
	outputFileName string
	workPoolNum    int
	noVulScan      bool

	PortScanTimeout = 3 * time.Second
)

// Get 获取配置
func Get() *Application {
	if application != nil {
		return application
	}
	application = &Application{
		SC:                  sC,
		PocId:               pocId,
		PocTags:             pocTags,
		FingerFile:          fingerFile,
		FingerMatch:         fingerMatch,
		PocFile:             pocFile,
		NoPing:              noPing,
		FullScan:            fullScan,
		SshKey:              sshKey,
		Verbose:             verbose,
		FofaQuery:           FofaQuery,
		FofaSize:            FofaSize,
		FofaKey:             FofaKey,
		ScanRandom:          scanRandom,
		HttpProxy:           httpProxy,
		Socks5Proxy:         socks5Proxy,
		Port:                port,
		Target:              target,
		TargetUrl:           targetUrl,
		TargetFile:          targetFile,
		OutputFileName:      outputFileName,
		WorkPoolNum:         workPoolNum,
		NoVulScan:           noVulScan,
		Vul:                 &AssetsVuls{},
		TLSHandshakeTimeout: 8 * time.Second,
		WebScanTimeout:      10 * time.Second,
		PortScanTimeout:     3 * time.Second,
		ICMPTimeOut:         2 * time.Second,
	}
	return application
}

func (c *Application) CheckProxy() bool {
	if c.Socks5Proxy != "" || c.HttpProxy != "" {
		return true
	}
	return false
}

// PrintDefaultUsage 打印默认配置信息
func (c *Application) PrintDefaultUsage() {
	fmt.Println("              _ ____                             ")
	fmt.Println("   ____ ___  (_) / /____  ___      ______ ___  __")
	fmt.Println("  / __ `__ \\/ / / //_/ / / / | /| / / __ `/ / / /")
	fmt.Println(" / / / / / / / / ,< / /_/ /| |/ |/ / /_/ / /_/ / ")
	fmt.Println("/_/ /_/ /_/_/_/_/|_|\\__, / |__/|__/\\__,_/\\__, /  ")
	fmt.Println("                   /____/               /____/   ")
	fmt.Println("                                 ", Version)
	fmt.Println("https://github.com/polite-007/Milkyway")
	fmt.Println("---------------Config-----------------------")
	fmt.Printf("threads: %d\n", c.WorkPoolNum)
	fmt.Printf("no-ping: %t\n", c.NoPing)
	fmt.Printf("no_vulscan: %t\n", c.NoVulScan)
	if c.OutputFileName != "" {
		fmt.Printf("output file: %s\n", c.OutputFileName)
	} else {
		fmt.Printf("output file: %s\n", "Null")
	}
	if c.Socks5Proxy == "" && c.HttpProxy == "" {
		fmt.Printf("proxy addr: %s\n", "Null")
	}
	if c.HttpProxy != "" {
		fmt.Printf("proxy addr: %s\n", c.HttpProxy)
	}
	if c.Socks5Proxy != "" {
		fmt.Printf("proxy addr: %s\n", c.Socks5Proxy)
	}
	fmt.Printf("scan-random: %t\n", c.ScanRandom)
	fmt.Println("---------------GettingTarget----------------")
}
