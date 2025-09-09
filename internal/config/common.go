package config

import (
	"github.com/polite007/Milkyway/pkg/logger"
	"net/url"
)

var a *AssetsResult

type Resp struct {
	Url        *url.URL
	Title      string
	Body       string
	Header     map[string][]string
	Server     string
	StatusCode int
	FavHash    string
	Cms        string
	Tags       []string
}

type PortProtocol struct {
	IP       string // 这个只给端口扫描的结果使用, 报告导出可以直接使用上层的IP字段就行
	Port     int
	Protocol string
	WebInfo  []*Resp // 为什么单个端口是切片？ 因为要为目录扫描服务
}

type ProtocolVul struct {
	Port     int
	Protocol string
	Message  string
}

type WebVul struct {
	VulUrl      string   // 漏洞地址
	VulName     string   // 漏洞名称
	Level       string   // 漏洞等级
	Description string   // 漏洞描述
	Recovery    string   // 漏洞修复意见
	Resp        []string // 响应包
	Req         []string // 请求包
}

type IpInfos struct {
	IP          string
	Ports       []*PortProtocol // 端口 列表
	ProtocolVul []*ProtocolVul  // 协议漏洞 列表
	WebVul      []*WebVul       // Web漏洞 列表
}

type UrlInfos struct {
	WebInfo *Resp
	WebVul  []*WebVul
}

type AssetsResult struct {
	IpInfos  []*IpInfos
	UrlInfos []*UrlInfos
}

func GetAssetsResult() *AssetsResult {
	if a != nil {
		return a
	}
	a = &AssetsResult{
		IpInfos:  []*IpInfos{},
		UrlInfos: []*UrlInfos{},
	}
	return a
}

func (a *AssetsResult) AddActiveIpList(ip []string) {
	for _, i := range ip {
		a.IpInfos = append(a.IpInfos, &IpInfos{
			IP: i,
		})
	}
}

// AddPortInfos 添加端口扫描结果到对应IP信息中
func (a *AssetsResult) AddPortInfos(portInfos []*PortScanTaskResult) {
	for _, portInfo := range portInfos {
		// 查找对应的IP信息
		var ipInfo *IpInfos
		for _, ip := range a.IpInfos {
			if ip.IP == portInfo.Host {
				ipInfo = ip
				break
			}
		}

		// 如果IP不存在，创建新的IP信息
		if ipInfo == nil {
			ipInfo = &IpInfos{
				IP:    portInfo.Host,
				Ports: []*PortProtocol{},
			}
			a.IpInfos = append(a.IpInfos, ipInfo)
		}

		// 检查端口是否已存在（去重）
		portExists := false
		for _, existingPort := range ipInfo.Ports {
			if existingPort.Port == portInfo.Port && existingPort.Protocol == portInfo.Protocol {
				portExists = true
				break
			}
		}

		// 如果端口不存在，添加新端口
		if !portExists {
			ipInfo.Ports = append(ipInfo.Ports, &PortProtocol{
				IP:       portInfo.Host,
				Port:     portInfo.Port,
				Protocol: portInfo.Protocol,
				WebInfo:  []*Resp{},
			})
		}
	}
}

// AddIPWebInfos 添加IP的Web扫描结果到对应端口信息中
func (a *AssetsResult) AddIPWebInfos(WebInfos []*WebScanTaskResult) {
	for _, webInfo := range WebInfos {
		// 查找对应的IP信息
		var ipInfo *IpInfos
		for _, ip := range a.IpInfos {
			if ip.IP == webInfo.IP {
				ipInfo = ip
				break
			}
		}

		// 如果IP不存在，创建新的IP信息
		if ipInfo == nil {
			ipInfo = &IpInfos{
				IP:    webInfo.IP,
				Ports: []*PortProtocol{},
			}
			a.IpInfos = append(a.IpInfos, ipInfo)
		}

		// 查找对应的端口信息
		var portInfo *PortProtocol
		for _, port := range ipInfo.Ports {
			if port.Port == webInfo.Port && port.Protocol == webInfo.Protocol {
				portInfo = port
				break
			}
		}

		// 如果端口不存在，创建新的端口信息
		if portInfo == nil {
			portInfo = &PortProtocol{
				IP:       webInfo.IP,
				Port:     webInfo.Port,
				Protocol: webInfo.Protocol,
				WebInfo:  []*Resp{},
			}
			ipInfo.Ports = append(ipInfo.Ports, portInfo)
		}

		// 添加Web信息到端口（去重）
		for _, web := range webInfo.WebInfo {
			// 检查Web信息是否已存在（基于URL去重）
			webExists := false
			for _, existingWeb := range portInfo.WebInfo {
				if existingWeb.Url.String() == web.Url.String() {
					webExists = true
					break
				}
			}

			if !webExists {
				portInfo.WebInfo = append(portInfo.WebInfo, web)
			}
		}
	}
}

// AddUrlWebInfos 添加URL的Web扫描结果到UrlInfos中
func (a *AssetsResult) AddUrlWebInfos(WebInfos []*Resp) {
	for _, webInfo := range WebInfos {
		// 检查URL是否已存在（去重）
		urlExists := false
		for _, existingUrl := range a.UrlInfos {
			if existingUrl.WebInfo.Url.String() == webInfo.Url.String() {
				urlExists = true
				break
			}
		}

		// 如果URL不存在，添加新的URL信息
		if !urlExists {
			a.UrlInfos = append(a.UrlInfos, &UrlInfos{
				WebInfo: webInfo,
				WebVul:  []*WebVul{},
			})
		}
	}
}

// AddDirScanWebInfos 添加目录扫描结果到对应IP的WebInfo中
func (a *AssetsResult) AddDirScanWebInfos(WebInfos []*DirScanTaskResult) {
	for _, dirInfo := range WebInfos {
		if dirInfo.Url != "" {
			// 这是URL扫描结果，添加到UrlInfos
			urlExists := false
			for _, existingUrl := range a.UrlInfos {
				if existingUrl.WebInfo.Url.String() == dirInfo.Url {
					urlExists = true
					break
				}
			}

			if !urlExists {
				a.UrlInfos = append(a.UrlInfos, &UrlInfos{
					WebInfo: dirInfo.ResPs,
					WebVul:  []*WebVul{},
				})
			}
		} else {
			// 这是IP扫描结果，添加到对应IP的端口信息中
			var ipInfo *IpInfos
			for _, ip := range a.IpInfos {
				if ip.IP == dirInfo.IP {
					ipInfo = ip
					break
				}
			}

			if ipInfo == nil {
				ipInfo = &IpInfos{
					IP:    dirInfo.IP,
					Ports: []*PortProtocol{},
				}
				a.IpInfos = append(a.IpInfos, ipInfo)
			}

			// 查找对应的端口信息
			var portInfo *PortProtocol
			for _, port := range ipInfo.Ports {
				if port.Port == dirInfo.Port {
					portInfo = port
					break
				}
			}

			if portInfo == nil {
				portInfo = &PortProtocol{
					IP:       dirInfo.IP,
					Port:     dirInfo.Port,
					Protocol: "http", // 目录扫描默认是http协议
					WebInfo:  []*Resp{},
				}
				ipInfo.Ports = append(ipInfo.Ports, portInfo)
			}

			// 添加目录扫描结果到WebInfo（去重）
			webExists := false
			for _, existingWeb := range portInfo.WebInfo {
				if existingWeb.Url.String() == dirInfo.ResPs.Url.String() {
					webExists = true
					break
				}
			}

			if !webExists {
				portInfo.WebInfo = append(portInfo.WebInfo, dirInfo.ResPs)
			}
		}
	}
}

// AddProtocolVul 添加协议漏洞到对应IP的ProtocolVul列表中
func (a *AssetsResult) AddProtocolVul(ip string, port int, protocol string, message string) {
	// 查找对应的IP信息
	var ipInfo *IpInfos
	for _, ipItem := range a.IpInfos {
		if ipItem.IP == ip {
			ipInfo = ipItem
			break
		}
	}

	// 如果IP不存在，创建新的IP信息
	if ipInfo == nil {
		ipInfo = &IpInfos{
			IP:          ip,
			Ports:       []*PortProtocol{},
			ProtocolVul: []*ProtocolVul{},
		}
		a.IpInfos = append(a.IpInfos, ipInfo)
	}

	// 检查协议漏洞是否已存在（去重）
	vulExists := false
	for _, existingVul := range ipInfo.ProtocolVul {
		if existingVul.Port == port && existingVul.Protocol == protocol && existingVul.Message == message {
			vulExists = true
			break
		}
	}

	// 如果漏洞不存在，添加新漏洞
	if !vulExists {
		ipInfo.ProtocolVul = append(ipInfo.ProtocolVul, &ProtocolVul{
			Port:     port,
			Protocol: protocol,
			Message:  message,
		})
	}
}

// AddWebPocVul 添加Web漏洞到对应IP或URL的WebVul列表中
func (a *AssetsResult) AddWebPocVul(p *WebPocVulScanPayload) {
	if p.Url != "" {
		// 这是URL漏洞，添加到UrlInfos
		var urlInfo *UrlInfos
		for _, urlTemp := range a.UrlInfos {
			if urlTemp.WebInfo.Url.String() == p.Url {
				urlInfo = urlTemp
				break
			}
		}

		if urlInfo == nil {
			urlInfo = &UrlInfos{
				WebInfo: p.Resp,
				WebVul:  []*WebVul{},
			}
			a.UrlInfos = append(a.UrlInfos, urlInfo)
		}

		// 添加Web漏洞
		webVul := &WebVul{
			VulUrl:      p.TargetUrl,
			VulName:     p.Poc.Info.Name,
			Level:       p.Poc.Info.Severity,
			Description: p.Poc.Info.Description,
			Recovery:    p.Poc.Info.Zombie,
			Resp:        []string{},
			Req:         []string{},
		}

		urlInfo.WebVul = append(urlInfo.WebVul, webVul)
	} else {
		// 这是IP漏洞，添加到对应IP的WebVul列表中
		var ipInfo *IpInfos
		for _, ip := range a.IpInfos {
			if ip.IP == p.IP {
				ipInfo = ip
				break
			}
		}

		if ipInfo == nil {
			ipInfo = &IpInfos{
				IP:     p.IP,
				Ports:  []*PortProtocol{},
				WebVul: []*WebVul{},
			}
			a.IpInfos = append(a.IpInfos, ipInfo)
		}

		// 添加Web漏洞
		webVul := &WebVul{
			VulUrl:      p.TargetUrl,
			VulName:     p.Poc.Info.Name,
			Level:       p.Poc.Info.Severity,
			Description: p.Poc.Info.Description,
			Recovery:    p.Poc.Info.Zombie,
			Resp:        []string{},
			Req:         []string{},
		}

		logger.OutLog(p.TargetUrl)
		ipInfo.WebVul = append(ipInfo.WebVul, webVul)
	}
}
