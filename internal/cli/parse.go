package cli

import (
	"github.com/polite007/Milkyway/config"
	"github.com/polite007/Milkyway/internal/service/initpak"
	"github.com/projectdiscovery/goflags"
	"os"
)

// ParseArgs 解析命令行参数
func ParseArgs() error {
	var (
		options = config.Get()
		err     error
	)
	flagSet := goflags.NewFlagSet()
	flagSet.SetDescription(config.Logo)
	// Input
	flagSet.CreateGroup("input", "Input",
		flagSet.StringVarP(&options.Target, "target", "t", "", "target to scan ('ip', 'cidr', 'ip segment')"),
		flagSet.StringVarP(&options.TargetUrl, "url", "u", "", "url to scan ('baidu.com')"),
		flagSet.StringVarP(&options.TargetFile, "exclude", "f", "", "target file to scan ('target.txt')"),
		flagSet.StringVarP(&options.FofaQuery, "query", "q", "", "fofa query to scan ('domain=baidu.com')"),
	)
	// Port
	flagSet.CreateGroup("port", "Port",
		flagSet.StringVarP(&options.Port, "port", "p", "default", "target port to scan ('small', 'company', 'all')"),
	)
	// Proxy
	flagSet.CreateGroup("proxy", "Proxy",
		flagSet.StringVarP(&options.HttpProxy, "http-proxy", "proxy", "", "http proxy ('http://127.0.0.1:8080')"),
		flagSet.StringVarP(&options.Socks5Proxy, "socks5", "s", "", "socks5 proxy ('socks5://127.0.0.1:8080')"),
	)
	// Scan Mode
	flagSet.CreateGroup("scan mode", "Scan Mode",
		flagSet.IntVarP(&options.WorkPoolNum, "concurrent", "c", 500, ""),
		flagSet.BoolVarP(&options.ScanRandom, "random", "r", false, ""),
		flagSet.StringVarP(&options.FofaKey, "fofa-key", "fk", "", "fofa key"),
		flagSet.IntVarP(&options.FofaSize, "fofa-size", "fs", 100, "fofa size"),
		flagSet.BoolVarP(&options.NoPing, "no-ping", "np", false, "skip the icmp/ping scan"),
		flagSet.BoolVarP(&options.NoDirScan, "no-dir", "nd", false, "skip the dir scan"), flagSet.BoolVarP(&options.Verbose, "verbose", "v", false, "show verbose output with protocol"),
		flagSet.BoolVarP(&options.FullScan, "full-scan", "fc", false, "fully detect protocols on open ports.By default,only common ones like 22-SSH and 3306-MySQL are identified"),
	)
	// Vul Mode
	flagSet.CreateGroup("vul mode", "Vul Mode",
		flagSet.BoolVarP(&options.NoVulScan, "no-vul", "nv", false, "skip the vul scan"),
		flagSet.BoolVarP(&options.FingerMatch, "no-match", "nm", false, "fingerprint rule matching prior to vulnerability scanning"),
		flagSet.StringVarP(&options.PocTags, "poc-tags", "pt", "", "comma-separated list of poc tags to scan for"),
		flagSet.StringVarP(&options.PocId, "poc-id", "pi", "", " poc id to scan for"),
	)
	// File Mod
	flagSet.CreateGroup("file mode", "File Mode",
		flagSet.StringVarP(&options.FingerFile, "finger-file", "ff", "", "path to the file containing fingerprint rules"),
		flagSet.StringVarP(&options.PocFile, "poc-file", "pf", "", "path to the file containing custom POCs (File Or Dir)"),
		flagSet.StringVarP(&options.DirDictFile, "dir-file", "df", "", "path to the file containing dir scan dict"),
	)
	if err = flagSet.Parse(); err != nil {
		return err
	}
	// 配置端口变量
	switch options.Port {
	case "all":
		options.Port = config.GetPorts().PortAll
	case "small":
		options.Port = config.GetPorts().PortSmall
	case "company":
		options.Port = config.GetPorts().PortCompany
	case "sql":
		options.Port = config.GetPorts().PortSql
	case "default":
		options.Port = config.GetPorts().PortDefault
	}
	// 初始化httpx代理
	if err = initpak.InitHttpProxy(); err != nil {
		return err
	}
	// 如果fofa key, 取系统变量 FOFA_KEY
	if options.FofaKey == "" {
		options.FofaKey = os.Getenv("FOFA_KEY")
	}
	return nil
}
