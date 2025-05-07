package cli

import (
	"fmt"
	"os"
	"strings"

	"github.com/polite007/Milkyway/config"
	"github.com/polite007/Milkyway/internal/service/initpak"
	"github.com/polite007/Milkyway/internal/utils/fofa"
	"github.com/polite007/Milkyway/pkg/fileutils"
	"github.com/polite007/Milkyway/pkg/strutils"
	"github.com/spf13/cobra"
)

// ParseTarget 获取ip列表和url列表
func ParseTarget() ([]string, []string, map[string][]int, error) {
	var (
		configs         = config.Get()
		errors          = config.GetErrors()
		fofaCore        = fofa.GetFofaCore(configs.FofaKey)
		designatedPorts = make(map[string][]int)
		list            []string
		ipList          []string
		urlList         []string
		err             error
	)
	if configs.FofaQuery != "" {
		if fofaCore.FofaKey == "" {
			panic("fofa_key为空或者不可用")
		}
		fmt.Printf("正在使用从fofa获取目标... \nfofa query: %s\n", config.Get().FofaQuery)
		fmt.Printf("你的fofa_key: %s", fofaCore.FofaKey)
		ipList, err = fofaCore.StatsIP(configs.FofaQuery, configs.FofaSize)
		if err != nil {
			return nil, nil, nil, err
		}
		return ipList, nil, nil, err
	}

	if configs.TargetFile != "" {
		list, err = fileutils.ReadLines(configs.TargetFile)
		if err != nil {
			return nil, nil, nil, err
		}
		for _, ip := range list {
			result, ok := strutils.IsDomain(ip)
			if ok {
				urlList = append(urlList, result...)
			} else {
				ipListSimple, err := ParseStr(strings.TrimSpace(ip), designatedPorts)
				if err != nil {
					return nil, nil, nil, err
				}
				ipList = strutils.UniqueAppend(ipList, ipListSimple...)
			}
		}
		return ipList, urlList, designatedPorts, err
	}

	if configs.TargetUrl != "" {
		urlListRaw := strings.Split(configs.TargetUrl, ",")
		for _, urlSimple := range urlListRaw {
			result, ok := strutils.IsDomain(urlSimple)
			if ok {
				urlList = append(urlList, result...)
			}
		}
		return nil, urlList, nil, err
	}

	if configs.Target != "" {
		ipList, err = ParseStr(configs.Target, nil)
		if err != nil {
			return nil, nil, nil, err
		}
		return ipList, nil, nil, err
	}

	return nil, nil, nil, errors.ErrTargetEmpty
}

// ParseArgs 解析命令行参数
func ParseArgs(cmd *cobra.Command) error {
	var (
		configs = config.Get()
		err     error
	)
	if configs.ScanRandom, err = cmd.Flags().GetBool("scan-random"); err != nil {
		return err
	}
	if configs.FingerFile, err = cmd.Flags().GetString("finger-file"); err != nil {
		return err
	}
	if configs.FofaKey, err = cmd.Flags().GetString("fofa-key"); err != nil {
		return err
	}
	configs.FofaSize, err = cmd.Flags().GetInt("fofa-size")
	if err != nil {
		return err
	}
	configs.NoPing, err = cmd.Flags().GetBool("no-ping")
	if err != nil {
		return err
	}
	configs.FingerMatch, err = cmd.Flags().GetBool("no-match")
	if err != nil {
		return err
	}
	configs.PocFile, err = cmd.Flags().GetString("poc-file")
	if err != nil {
		return err
	}
	configs.OutputFileName, err = cmd.Flags().GetString("output")
	if err != nil {
		return err
	}
	configs.Socks5Proxy, err = cmd.Flags().GetString("socks5")
	if err != nil {
		return err
	}
	configs.WorkPoolNum, err = cmd.Flags().GetInt("concurrent")
	if err != nil {
		return err
	}
	configs.Target, err = cmd.Flags().GetString("target")
	if err != nil {
		return err
	}
	configs.TargetFile, err = cmd.Flags().GetString("file")
	if err != nil {
		return err
	}
	configs.HttpProxy, err = cmd.Flags().GetString("http-proxy")
	if err != nil {
		return err
	}
	configs.Port, err = cmd.Flags().GetString("port")
	if err != nil {
		return err
	}
	configs.TargetUrl, err = cmd.Flags().GetString("url")
	if err != nil {
		return err
	}
	configs.FofaQuery, err = cmd.Flags().GetString("fofa-query")
	if err != nil {
		return err
	}
	configs.Verbose, err = cmd.Flags().GetBool("verbose")
	if err != nil {
		return err
	}
	configs.FullScan, err = cmd.Flags().GetBool("full-scan")
	if err != nil {
		return err
	}
	configs.PocId, err = cmd.Flags().GetString("poc-id")
	if err != nil {
		return err
	}
	configs.PocTags, err = cmd.Flags().GetString("poc-tags")
	if err != nil {
		return err
	}
	configs.NoVulScan, err = cmd.Flags().GetBool("no-vulscan")
	if err != nil {
		return err
	}

	switch configs.Port {
	case "all":
		configs.Port = config.PortAll
	case "small":
		configs.Port = config.PortSmall
	case "company":
		configs.Port = config.PortCompany
	case "sql":
		configs.Port = config.PortSql
	case "default":
		configs.Port = config.PortDefault
	}
	// 初始化httpx代理
	if err = initpak.InitHttpProxy(); err != nil {
		return err
	}
	if configs.FofaKey == "" {
		configs.FofaKey = os.Getenv("FOFA_KEY")
	}
	return nil
}
