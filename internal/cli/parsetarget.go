package cli

import (
	"fmt"
	"github.com/polite007/Milkyway/config"
	"github.com/polite007/Milkyway/internal/utils/fofa"
	"github.com/polite007/Milkyway/pkg/fileutils"
	"github.com/polite007/Milkyway/pkg/strutils"
	"strings"
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
		fmt.Println("---------------GettingTarget---------------")
		if fofaCore.FofaKey == "" {
			panic("fofa_key为空或者不可用")
		}
		fmt.Printf("正在使用从fofa获取目标... \nfofa query: %s\n", config.Get().FofaQuery)
		fmt.Printf("你的fofa_key: %s\n", fofaCore.FofaKey)
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
