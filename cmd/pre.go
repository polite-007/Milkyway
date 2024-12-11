package cmd

import (
	"fmt"
	"github.com/polite007/Milkyway/common/const"
	"github.com/polite007/Milkyway/common/fofa"
	"github.com/polite007/Milkyway/common/http_custom"
	"github.com/polite007/Milkyway/pkg/neutron"
	"github.com/polite007/Milkyway/pkg/utils"
	"github.com/spf13/cobra"
	"os"
	"strings"
)

func ParseTarget() ([]string, []string, error) {
	var (
		ipList  []string
		urlList []string
		err     error
	)
	if _const.FofaKey != "" && _const.FofaQuery != "" {
		fmt.Printf("正在使用从fofa获取目标。。。 fofa query: %s\n", _const.FofaQuery)
		ipList, err = fofa.StatsIP(_const.FofaQuery)
		if err != nil {
			return nil, nil, err
		}
		return ipList, nil, err
	}

	if _const.TargetFile != "" {
		list, err := utils.File.ReadLines(_const.TargetFile)
		if err != nil {
			return nil, nil, err
		}
		for _, ip := range list {
			result, ok := utils.IsDomain(ip)
			if ok {
				urlList = append(urlList, result...)
			} else {
				ipListSimple, err := utils.ParseStr(strings.TrimSpace(ip))
				if err != nil {
					return nil, nil, err
				}
				ipList = utils.UniqueAppend(ipList, ipListSimple...)
			}
		}
		return ipList, urlList, nil
	}

	if _const.TargetUrl != "" {
		urlListRaw := strings.Split(_const.TargetUrl, ",")
		for _, urlSimple := range urlListRaw {
			result, ok := utils.IsDomain(urlSimple)
			if ok {
				urlList = append(urlList, result...)
			}
		}
		return nil, urlList, nil
	}

	if _const.Target != "" {
		ipList, err = utils.ParseStr(_const.Target)
		if err != nil {
			return nil, nil, err
		}
		return ipList, nil, nil
	}

	return nil, nil, _const.ErrTargetEmpty
}

func ParseArgs(cmd *cobra.Command) error {
	var (
		err error
	)
	if _const.ScanRandom, err = cmd.Flags().GetBool("scan-random"); err != nil {
		return err
	}
	if _const.FingerFile, err = cmd.Flags().GetString("finger-file"); err != nil {
		return err
	}
	if _const.FofaKey, err = cmd.Flags().GetString("fofa-key"); err != nil {
		return err
	}
	_const.FofaSize, err = cmd.Flags().GetInt("fofa-size")
	if err != nil {
		return err
	}
	_const.NoPing, err = cmd.Flags().GetBool("no-ping")
	if err != nil {
		return err
	}
	_const.FingerMatch, err = cmd.Flags().GetBool("no-match")
	if err != nil {
		return err
	}
	_const.PocFile, err = cmd.Flags().GetString("poc-file")
	if err != nil {
		return err
	}
	_const.OutputFileName, err = cmd.Flags().GetString("output")
	if err != nil {
		return err
	}
	_const.Socks5Proxy, err = cmd.Flags().GetString("socks5")
	if err != nil {
		return err
	}
	_const.WorkPoolNum, err = cmd.Flags().GetInt("concurrent")
	if err != nil {
		return err
	}
	_const.Target, err = cmd.Flags().GetString("target")
	if err != nil {
		return err
	}
	_const.TargetFile, err = cmd.Flags().GetString("file")
	if err != nil {
		return err
	}
	_const.HttpProxy, err = cmd.Flags().GetString("http-proxy")
	if err != nil {
		return err
	}
	_const.Port, err = cmd.Flags().GetString("port")
	if err != nil {
		return err
	}
	_const.TargetUrl, err = cmd.Flags().GetString("url")
	if err != nil {
		return err
	}
	_const.FofaQuery, err = cmd.Flags().GetString("fofa-query")
	if err != nil {
		return err
	}
	_const.Verbose, err = cmd.Flags().GetBool("verbose")
	if err != nil {
		return err
	}
	_const.FullScan, err = cmd.Flags().GetBool("full-scan")
	if err != nil {
		return err
	}
	_const.PocId, err = cmd.Flags().GetString("poc-id")
	if err != nil {
		return err
	}
	_const.PocTags, err = cmd.Flags().GetString("poc-tags")
	if err != nil {
		return err
	}

	switch _const.Port {
	case "all":
		_const.Port = _const.PortAll
	case "small":
		_const.Port = _const.PortSmall
	case "company":
		_const.Port = _const.PortCompany
	case "sql":
		_const.Port = _const.PortSql
	case "default":
		_const.Port = _const.PortDefault
	}
	if err = initHttpProxy(); err != nil {
		return err
	}
	if _const.FofaKey == "" {
		_const.FofaKey = os.Getenv("FOFA_KEY")
	}
	return nil
}

func initHttpProxy() error {
	if _const.Socks5Proxy != "" {
		return http_custom.WithProxy(_const.Socks5Proxy)
	}
	if _const.HttpProxy != "" {
		return http_custom.WithProxy(_const.HttpProxy)
	}
	return nil
}

func initPoc() {
	fmt.Printf("[*] 初始化poc库\n")
	neutron.InitPoc() // 初始化poc
	neutron.InitNculeiProxy()
}

func printDefaultUsage2() {
	fmt.Println("---------------Config-----------------")
	fmt.Printf("threads: %d\n", _const.WorkPoolNum)
	fmt.Printf("no-ping: %t\n", _const.NoPing)
	if _const.OutputFileName != "" {
		fmt.Printf("output file: %s\n", _const.OutputFileName)
	} else {
		fmt.Printf("output file: %s\n", "Null")
	}
	if _const.Socks5Proxy == "" && _const.HttpProxy == "" {
		fmt.Printf("proxy addr: %s\n", "Null")
	}
	if _const.HttpProxy != "" {
		fmt.Printf("proxy addr: %s\n", _const.HttpProxy)
	}
	if _const.Socks5Proxy != "" {
		fmt.Printf("proxy addr: %s\n", _const.Socks5Proxy)
	}
	fmt.Printf("scan-random: %t\n", _const.ScanRandom)
}

func printDefaultUsage1() {
	fmt.Println(_const.Logo)
	fmt.Println("---------------GettingTarget----------")
}

func MergeMaps(m1, m2 map[string][]*_const.PortProtocol) map[string][]*_const.PortProtocol {
	result := make(map[string][]*_const.PortProtocol)
	for k, v := range m1 {
		result[k] = v
	}
	for k, v := range m2 {
		if existingSlice, ok := result[k]; ok {
			result[k] = append(existingSlice, v...)
		} else {
			result[k] = v
		}
	}

	return result
}
