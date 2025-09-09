package config

import (
	"github.com/polite007/Milkyway/pkg/neutron/templates"
	"strings"
)

type PortScanTaskPayload struct {
	IP    string
	Ports []int
}

type PortScanTaskResult struct {
	Host     string // 这个其实就是IP
	Port     int
	Protocol string
}

type PortScanTaskResultTwo struct {
	Host  string
	Ports []struct {
		Port     int
		Protocol string
	}
}

func TransformPToW(results []*PortScanTaskResult) []*WebScanTaskPayload {
	webScanTaskPayload := make([]*WebScanTaskPayload, 0, len(results))
	for _, p := range results {
		webScanTaskPayload = append(webScanTaskPayload, &WebScanTaskPayload{
			PortScanTaskResult: *p,
		})
	}
	return webScanTaskPayload
}

type WebScanTaskPayload struct {
	PortScanTaskResult
}

type WebScanTaskResult struct {
	PortProtocol
}

func (a *AssetsResult) GetDirScanTaskPayload() []*DirScanTaskPayload {
	var dirScanTaskPayload []*DirScanTaskPayload
	// 填充ip的
	for _, i := range a.IpInfos {
		for _, p := range i.Ports {
			if len(p.WebInfo) > 0 {
				web := p.WebInfo[0]
				// 判断status_code
				if web.StatusCode == 404 || web.StatusCode == 403 || web.StatusCode == 400 || (web.StatusCode == 200 && len(web.Body) < 100) {
					dirScanTaskPayload = append(dirScanTaskPayload, &DirScanTaskPayload{
						IP:   i.IP,
						Port: p.Port,
						Url:  "", // 置为空
						Resp: web,
					})
				}
			}
		}
	}

	// 填充url的
	for _, i := range a.UrlInfos {
		web := i.WebInfo
		if web.StatusCode == 404 || web.StatusCode == 403 || web.StatusCode == 400 || (web.StatusCode == 200 && len(web.Body) < 100) {
			dirScanTaskPayload = append(dirScanTaskPayload, &DirScanTaskPayload{
				IP:   "", // 置为空
				Port: 0,  // 置为空
				Url:  i.WebInfo.Url.String(),
				Resp: i.WebInfo,
			})
		}
	}

	return dirScanTaskPayload
}

type DirScanTaskPayload struct {
	IP   string
	Port int
	Url  string // 通过这个是否空值来判断是url还是ip
	Path string // 给目录扫描的path使用
	Resp *Resp
}

func (a *DirScanTaskPayload) GetHost() string {
	return strings.TrimRight(a.Resp.Url.Host, "/")
}

type DirScanTaskResult struct {
	IP    string
	Port  int
	Url   string // 通过这个是否空值来判断是url还是ip
	ResPs *Resp  // 承担目录扫描, 存新的响应
}

func (a *AssetsResult) GetProtocolVulScanTaskPayload() []*ProtocolVulScanTaskPayload {
	var payload []*ProtocolVulScanTaskPayload
	for _, i := range a.IpInfos {
		for _, j := range i.Ports {
			// 去掉web, unknown
			if j.Protocol == "http" || j.Protocol == "https" || j.Protocol == "" {
				continue
			}

			payload = append(payload, &ProtocolVulScanTaskPayload{
				IP:       i.IP,
				Port:     j.Port,
				Protocol: j.Protocol,
			})
		}
	}
	return payload
}

type ProtocolVulScanTaskPayload struct {
	IP       string
	Port     int
	Protocol string
}

func (a *AssetsResult) GetWebPocVulScanPayload() []*WebPocVulScanPayload {
	var dirScanTaskPayload []*WebPocVulScanPayload
	// 填充ip的
	for _, i := range a.IpInfos {
		for _, p := range i.Ports {
			// 这里已经经历了目录扫描的洗礼了, 直接可以使用切片
			for _, web := range p.WebInfo {
				// 判断status_code
				if web.StatusCode == 404 {
					continue
				}

				dirScanTaskPayload = append(dirScanTaskPayload, &WebPocVulScanPayload{
					IP:   i.IP,
					Port: p.Port,
					Url:  "", // 置为空
					Resp: web,
				})
			}
		}
	}

	// 填充url的
	for _, i := range a.UrlInfos {
		web := i.WebInfo
		if web.StatusCode == 404 {
			continue
		}

		dirScanTaskPayload = append(dirScanTaskPayload, &WebPocVulScanPayload{
			IP:   "", // 置为空
			Port: 0,  // 置为空
			Url:  i.WebInfo.Url.String(),
			Resp: i.WebInfo,
		})
	}

	return dirScanTaskPayload
}

type WebPocVulScanPayload struct {
	IP   string
	Port int
	Url  string // 通过这个是否空值来判断是url还是ip
	Resp *Resp
	// 下面是给漏洞扫描使用的
	Poc       *templates.Template
	TargetUrl string
}
