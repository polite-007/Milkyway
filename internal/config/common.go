package config

import (
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

func (a *AssetsResult) AddPortInfos(portInfos []*PortScanTaskResult) {

}

func (a *AssetsResult) AddIPWebInfos(WebInfos []*WebScanTaskResult) {

}

func (a *AssetsResult) AddUrlWebInfos(WebInfos []*Resp) {

}

func (a *AssetsResult) AddDirScanWebInfos(WebInfos []*DirScanTaskResult) {

}

func (a *AssetsResult) AddProtocolVul(ip string, port int, protocol string, message string) {

}

func (a *AssetsResult) AddWebPocVul(p *WebPocVulScanPayload) {

}
