package task_raw

import (
	"fmt"
	"strings"

	"github.com/polite007/Milkyway/config"
	"github.com/polite007/Milkyway/internal/cli"
	"github.com/polite007/Milkyway/internal/common"
	"github.com/polite007/Milkyway/internal/service/initpak"
	"github.com/polite007/Milkyway/internal/utils/httpx"
	"github.com/polite007/Milkyway/pkg/color"
	"github.com/polite007/Milkyway/pkg/logger"
	"github.com/polite007/Milkyway/pkg/strutils"
)

// IpActiveScan 探测存活IP
func IpActiveScan(ipList []string) ([]string, error) {
	logger.OutLog("---------------IpActiveScan-----------------\n")
	var err error
	configs := config.Get()
	ipAliveList := ipList
	if configs.CheckProxy() {
		logger.OutLog(fmt.Sprintf("代理模式暂不支持ICMP探测,直接进行端口扫描\n"))
	} else {
		if !configs.NoPing {
			ipAliveList, err = newIPScanTask(ipList)
			if err != nil {
				return nil, err
			}
		}
	}
	logger.OutLog(fmt.Sprintf("[*] Alive IP Num: %d\n", len(ipAliveList)))
	return ipAliveList, err
}

// PortActiveScan 探测开放端口&协议识别
func PortActiveScan(ipAliveList []string) ([]*common.IpPortProtocol, error) {
	logger.OutLog("---------------PortActiveScan---------------\n")
	var (
		portScanTaskList []*common.IpPorts
		aliveIpPortList  *common.TargetList
		err              error
	)
	for _, ip := range ipAliveList {
		portScanTaskList = append(portScanTaskList, &common.IpPorts{
			IP:    ip,
			Ports: cli.ParsePort(config.Get().Port),
		})
	}
	if config.Get().ScanRandom {
		aliveIpPortList, err = newPortScanTask(portScanTaskList)
	} else {
		aliveIpPortList, err = newPortScanTaskRandom(portScanTaskList)
	}
	if err != nil {
		return nil, err
	} else {
		ipPortList := aliveIpPortList.GetIpPorts()
		for _, d := range ipPortList {
			logger.OutLog(fmt.Sprintf("Found %d ports on host %s\n", len(d.Ports), d.IP))
		}
		return aliveIpPortList.GetIpPortProtocols(), nil
	}
}

// WebActiveScan 扫描非web协议的目标,
func WebActiveScan(ipPortList []*common.IpPortProtocol) ([]*common.IpPortProtocol, []*httpx.Resps, error) {
	logger.OutLog("---------------WebActiveScan----------------\n")
	return newWebScanTask(ipPortList)
}

// WebScanWithDomain url网站扫描
func WebScanWithDomain(targetUrl []string) ([]*httpx.Resps, error) {
	logger.OutLog("---------------WebScanWithDomain------------\n")
	return newWebScanWithDomainTask(targetUrl)
}

// ProtocolVulScan 协议漏洞扫描
func ProtocolVulScan(ipPortList []*common.IpPortProtocol) error {
	logger.OutLog("---------------ProtocolVulScan--------------\n")
	return newProtocolVulScan(ipPortList)
}

// WebPocVulScan 网站漏洞扫描
func WebPocVulScan(WebList []*httpx.Resps) error {
	logger.OutLog("---------------WebPocVulScan----------------\n")
	// 初始化poc引擎
	if err := initpak.InitPocEngine(); err != nil {
		return err
	}
	// 打印配置
	if !config.Get().FingerMatch {
		fmt.Printf("[*] %s\n", color.Yellow("当前扫描模式是匹配指纹,如需全量扫描请更改-m,但全量扫描会有误报,请自己判断"))
	} else {
		fmt.Printf("[*] %s\n", color.Yellow("当前扫描模式是全量扫描,如需进行指纹匹配请更改去掉-m"))
	}

	// 匹配漏洞
	var pocTask []*PocTask
	for _, poc := range initpak.PocsList {
		for _, web := range WebList {
			if web.StatusCode == 404 {
				continue
			}
			if !config.Get().FingerMatch {
				if len(web.Tags) != 0 {
					if strutils.HasCommonElement(web.Tags, strings.Split(poc.Info.Tags, ",")) {
						pocTask = append(pocTask, &PocTask{
							Poc:       poc,
							TargetUrl: web.Url.String(),
						})
						continue
					}
				}
				if web.Cms != "" {
					if strings.Contains(poc.Info.Name, web.Cms) || strings.Contains(poc.Info.Tags, strings.ToLower(web.Cms)) {
						pocTask = append(pocTask, &PocTask{
							Poc:       poc,
							TargetUrl: web.Url.String(),
						})
						continue
					}
				}
			} else {
				pocTask = append(pocTask, &PocTask{
					Poc:       poc,
					TargetUrl: web.Url.String(),
				})
			}
		}
	}
	logger.OutLog(fmt.Sprintf("[*] 下发%d个漏洞扫描任务\n", len(pocTask)))
	return newWebPocVulScan(pocTask)
}
