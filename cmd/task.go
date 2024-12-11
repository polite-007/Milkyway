package cmd

import (
	"fmt"
	_const "github.com/polite007/Milkyway/common/const"
	"github.com/polite007/Milkyway/common/http_custom"
	"github.com/polite007/Milkyway/pkg/log"
	"github.com/polite007/Milkyway/pkg/neutron"
	"github.com/polite007/Milkyway/pkg/utils"
	"github.com/polite007/Milkyway/task"
	"strings"
)

func CheckProxy() string {
	if _const.Socks5Proxy == "" && _const.HttpProxy == "" {
		return ""
	}
	if _const.Socks5Proxy != "" {
		return "socks5"
	}

	if _const.HttpProxy != "" {
		return "http"
	}
	return ""
}

func IpPortScan(ipList []string) (map[string][]*_const.PortProtocol, error) {
	fmt.Println("---------------InfoScan---------------")
	// 探测存活IP
	var (
		ipAliveList = ipList
		err         error
	)
	if CheckProxy() != "" {
		fmt.Println("代理模式暂不支持ICMP探测,直接进行端口扫描")
	} else {
		if !_const.NoPing {
			ipAliveList, err = task.NewIPScanTask(ipList)
			if err != nil {
				return nil, err
			}
		}
	}
	logOut := fmt.Sprintf("[*] Alive IP Num: %d\n", len(ipAliveList))
	log.OutLog(logOut)

	// 端口扫描
	portScanTaskList := map[string][]int{}
	for _, ip := range ipAliveList {
		portScanTaskList[ip] = append(portScanTaskList[ip], utils.ParsePort(_const.Port)...)
	}
	var aliveIpPortList map[string][]*_const.PortProtocol
	if _const.ScanRandom {
		aliveIpPortList, err = task.NewPortScanTask(portScanTaskList)
	} else {
		aliveIpPortList, err = task.NewPortScanTask1(portScanTaskList)
	}
	if err != nil {
		return nil, err
	} else {
		for ip, ports := range aliveIpPortList {
			logOut = fmt.Sprintf("Found %d ports on host %s\n", len(ports), ip)
			log.OutLog(logOut)
		}
		return aliveIpPortList, nil
	}
}

func WebScan(ipPortList map[string][]*_const.PortProtocol) (map[string][]*_const.PortProtocol, []*http_custom.Resps, error) {
	fmt.Println("---------------WebScan----------------")
	return task.NewWebScanTask(ipPortList)
}

func ProtocolVulScan(ipPortList map[string][]*_const.PortProtocol) error {
	fmt.Println("---------------VulScan----------------")
	return task.NewProtocolVulScan(ipPortList)
}

func WebScanWithDomain(targetUrl []string) ([]*http_custom.Resps, error) {
	return task.NewWebScanWithDomainTask(targetUrl)
}

func WebPocVulScan(WebList []*http_custom.Resps) error {
	initPoc()
	if !_const.FingerMatch {
		fmt.Printf("[*] %s\n", utils.Yellow("当前扫描模式是匹配指纹,如需全量扫描请更改-m,但全量扫描会有误报,请自己判断"))
	} else {
		fmt.Printf("[*] %s\n", utils.Yellow("当前扫描模式是全量扫描,如需进行指纹匹配请更改去掉-m"))
	}
	var pocTask []*task.PocTask
	for _, poc := range neutron.PocsList {
		for _, web := range WebList {
			if web.StatusCode == 404 {
				continue
			}
			if !_const.FingerMatch {
				if len(web.Tags) != 0 {
					if utils.HasCommonElement(web.Tags, strings.Split(poc.Info.Tags, ",")) {
						pocTask = append(pocTask, &task.PocTask{
							Poc:       poc,
							TargetUrl: web.Url.String(),
						})
						continue
					}
				}
				if web.Cms != "" {
					if strings.Contains(poc.Info.Name, web.Cms) || strings.Contains(poc.Info.Tags, strings.ToLower(web.Cms)) {
						pocTask = append(pocTask, &task.PocTask{
							Poc:       poc,
							TargetUrl: web.Url.String(),
						})
						continue
					}
				}
			} else {
				pocTask = append(pocTask, &task.PocTask{
					Poc:       poc,
					TargetUrl: web.Url.String(),
				})
			}
		}
	}
	result := fmt.Sprintf("[*] 下发%d个漏洞扫描任务\n", len(pocTask))
	log.OutLog(result)
	return task.NewWebPocVulScan(pocTask)
}
