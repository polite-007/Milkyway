package config

import (
	"fmt"
	"time"
)

type Options struct {
	// input
	Target     string
	TargetUrl  string
	TargetFile string
	FofaQuery  string
	// port
	Port string
	// proxy
	HttpProxy   string
	Socks5Proxy string
	// scan mode
	NoDirScan   bool
	WorkPoolNum int
	ScanRandom  bool
	FofaKey     string
	FofaSize    int
	Verbose     bool
	FullScan    bool
	NoPing      bool
	// vul mode
	NoVulScan   bool
	FingerMatch bool
	PocId       string
	PocTags     string
	// file mode
	PocFile     string
	FingerFile  string
	DirDictFile string
	// exp mode
	SC     string
	SshKey string
	// result
	// timeout mode
	TLSHandshakeTimeout time.Duration
	WebScanTimeout      time.Duration
	PortScanTimeout     time.Duration
	ICMPTimeOut         time.Duration
}

var application *Options

// Get 获取配置
func Get() *Options {
	if application != nil {
		return application
	}
	application = &Options{
		TLSHandshakeTimeout: 8 * time.Second,
		WebScanTimeout:      10 * time.Second,
		PortScanTimeout:     3 * time.Second,
		ICMPTimeOut:         2 * time.Second,
	}
	return application
}

func (c *Options) CheckProxy() bool {
	if c.Socks5Proxy != "" || c.HttpProxy != "" {
		return true
	}
	return false
}

// PrintDefaultUsage 打印默认配置信息
func (c *Options) PrintDefaultUsage() {
	fmt.Println(Logo)
	fmt.Println("\n---------------Scan Config------------------")
	fmt.Printf("threads:          %d\n", c.WorkPoolNum)
	fmt.Printf("no-ping:          %t\n", c.NoPing)
	fmt.Printf("no_vulscan:       %t\n", c.NoVulScan)
	fmt.Printf("no_dirscan:       %t\n", c.NoDirScan)
	if c.Socks5Proxy == "" && c.HttpProxy == "" {
		fmt.Printf("proxy addr:       %s\n", "Null")
	}
	if c.HttpProxy != "" {
		fmt.Printf("proxy addr:       %s\n", c.HttpProxy)
	}
	if c.Socks5Proxy != "" {
		fmt.Printf("proxy addr:       %s\n", c.Socks5Proxy)
	}
	fmt.Printf("scan_random:      %t\n", c.ScanRandom)
	fmt.Printf("nuclei_template:  %s\n", NucleiTempLateVersion)
}
