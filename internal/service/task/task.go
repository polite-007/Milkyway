package task

import (
	"fmt"
	"github.com/polite007/Milkyway/internal/config"
	"github.com/polite007/Milkyway/pkg/fileutils"
	"github.com/polite007/Milkyway/static"
	"slices"
	"strings"

	"github.com/polite007/Milkyway/internal/service/init"
	"github.com/polite007/Milkyway/pkg/color"
	"github.com/polite007/Milkyway/pkg/logger"
	"github.com/polite007/Milkyway/pkg/strutils"
)

// 参数:
//   - ipList: 需要扫描的IP地址列表。
//
// 返回值:
//   - []string: 活跃的IP地址列表。
//   - error: 如果扫描过程中发生错误，则返回错误信息；否则返回nil。

func IpActiveScan(ips []string) ([]string, error) {
	logger.OutLog("---------------IpActiveScan-----------------\n")
	var err error
	configs := config.Get()
	ipAliveList := ips
	if configs.CheckProxy() {
		logger.OutLog(fmt.Sprintf("代理模式暂不支持ICMP探测,直接进行端口扫描\n"))
	} else {
		if !configs.NoPing {
			ipAliveList, err = newIPScanTask(ips)
			if err != nil {
				return nil, err
			}
		}
	}
	logger.OutLog(fmt.Sprintf("[*] Alive IP Num: %d\n", len(ipAliveList)))
	return ipAliveList, err
}

// 参数:
//   - ips: 需要扫描的IP地址列表。
//   - port: 需要扫描的端口列表。
//   - random: 是否启用随机扫描模式。如果为true，则使用随机顺序扫描端口；否则按顺序扫描。
//
// 返回值:
//   - []*common.IpPortProtocol: 扫描到的活跃IP、端口和协议信息列表。
//   - error: 如果扫描过程中发生错误，则返回错误信息；否则返回nil。

func PortActiveScan(ips []string, port []int, DesignatedPorts map[string][]int) ([]*config.PortScanTaskResult, error) {
	logger.OutLog("---------------PortActiveScan---------------\n")
	var (
		portScanTaskList []*config.PortScanTaskPayload
		err              error
	)

	for _, ip := range ips {
		targetPort := port
		if DesignatedPorts != nil {
			if targetPortTemp, ok := DesignatedPorts[ip]; ok {
				targetPort = targetPortTemp
			}
		}
		portScanTaskList = append(portScanTaskList, &config.PortScanTaskPayload{
			IP:    ip,
			Ports: targetPort,
		})
	}

	IpPortList, err := newPortScanTask(portScanTaskList, config.Get().ScanRandom)
	if err != nil {
		return nil, err
	}

	IpPortListTwo := TransformBatch(IpPortList)

	for _, d := range IpPortListTwo {
		logger.OutLog(fmt.Sprintf("Found %d ports on host %s\n", len(d.Ports), d.Host))
	}

	return IpPortList, err
}

// WebActiveScan 扫描非web协议的目标,
func WebActiveScan(ipPortList []*config.WebScanTaskPayload) ([]*config.WebScanTaskResult, error) {
	logger.OutLog("---------------WebActiveScan----------------\n")
	newIpPortList := slices.DeleteFunc(ipPortList, func(p *config.WebScanTaskPayload) bool {
		return p.Protocol != ""
	})
	return newWebScanTask(newIpPortList)
}

// WebScanWithDomain 根据url探测
func WebScanWithDomain(targetUrl []string) ([]*config.Resp, error) {
	logger.OutLog("---------------WebScanWithDomain------------\n")
	return newWebScanWithDomainTask(targetUrl)
}

// ProtocolVulScan 协议漏洞扫描
func ProtocolVulScan(ipPortList []*config.ProtocolVulScanTaskPayload) error {
	logger.OutLog("---------------ProtocolVulScan--------------\n")
	return newProtocolVulScan(ipPortList)
}

// WebPocVulScan 网站漏洞扫描
func WebPocVulScan(WebList []*config.WebPocVulScanPayload) error {
	logger.OutLog("---------------WebPocVulScan----------------\n")
	// 初始化poc引擎
	if err := initpak.InitPocEngine(); err != nil {
		return err
	}
	// 打印配置
	if !config.Get().FingerMatch {
		fmt.Printf("[*] %s\n", color.Yellow("当前扫描模式是匹配指纹, 如需全量扫描添加 -nm "))
	} else {
		fmt.Printf("[*] %s\n", color.Yellow("当前扫描模式是全量扫描(此扫描会有误报), 如需进行指纹匹配去掉 -nm "))
	}

	// 匹配漏洞
	var pocTask []*config.WebPocVulScanPayload
	for _, poc := range initpak.PocsList {
		for _, webTemp := range WebList {
			web := webTemp.Resp

			shouldAdd := false

			if !config.Get().FingerMatch {
				// 标签匹配
				if len(web.Tags) > 0 && strutils.HasCommonElement(web.Tags, strings.Split(poc.Info.Tags, ",")) {
					shouldAdd = true
				}

				// CMS 匹配
				if !shouldAdd && web.Cms != "" {
					if strings.Contains(poc.Info.Name, web.Cms) ||
						strings.Contains(poc.Info.Tags, strings.ToLower(web.Cms)) {
						shouldAdd = true
					}
				}
			} else {
				shouldAdd = true
			}

			if shouldAdd {
				pocTask = append(pocTask, &config.WebPocVulScanPayload{
					IP:        webTemp.IP,
					Port:      webTemp.Port,
					Url:       webTemp.Url,
					Poc:       poc,
					TargetUrl: web.Url.String(),
				})
				continue
			}
		}
	}
	logger.OutLog(fmt.Sprintf("[*] 下发%d个漏洞扫描任务\n", len(pocTask)))
	return newWebPocVulScan(pocTask)
}

func DirScan(t []*config.DirScanTaskPayload) ([]*config.DirScanTaskResult, error) {
	logger.OutLog("---------------DirScan----------------------\n")
	var (
		dirListByte []byte
		dirList     []string
		err         error
	)

	if dirListByte, err = static.EmbedFS.ReadFile("dict/dir.txt"); err != nil {
		return nil, err
	} else {
		dirList = strings.Split(string(dirListByte), "\n")
	}

	if config.Get().DirDictFile != "" {
		dirList, err = fileutils.ReadLines(config.Get().DirDictFile)
		if err != nil {
			return nil, err
		}
	}
	logger.OutLog(fmt.Sprintf("[*] 当前字典数: %d\n", len(dirList)))

	return newDirScanTask(t, dirList)
}
