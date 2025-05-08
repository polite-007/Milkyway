package config

import (
	"net/url"
	"sync"
	"time"
)

// todo 存放通用结构体

type Resps struct {
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

type ProtocolVul struct {
	IP       string
	Port     int
	Protocol string
	Message  string
}

type IpPortProtocol struct {
	IP       string
	Port     int
	Protocol string
}

type WebVul struct {
	VulUrl      string
	VulName     string
	Level       string // 漏洞等级
	Description string // 漏洞描述
	Recovery    string // 漏洞修复意见
}

type AssetsVuls struct {
	IpActiveList []string          // 存活的ip列表
	WebList      []*Resps          // Web 列表
	IpPortList   []*IpPortProtocol // IpPort 列表
	ProtocolVul  []*ProtocolVul    // 协议漏洞 列表
	WebVul       []*WebVul         // Web 漏洞列表
}

// AddProtocolVul 添加协议漏洞
func (i *AssetsVuls) AddProtocolVul(ip string, port int, protocol string, message string) {
	i.ProtocolVul = append(i.ProtocolVul, &ProtocolVul{
		IP:       ip,
		Port:     port,
		Protocol: protocol,
		Message:  message,
	})
}

// AddWebVul 添加 Web 漏洞
func (i *AssetsVuls) AddWebVul(vulUrl, vulName, des, recovery, level string) {
	i.WebVul = append(i.WebVul, &WebVul{
		VulUrl:      vulUrl,
		VulName:     vulName,
		Description: des,
		Level:       level,
		Recovery:    recovery,
	})
}

type IpPorts struct {
	IP    string
	Ports []int
}

type IpPortList struct {
	IP    string
	Ports []*PortProtocol
}

type PortProtocol struct {
	Port     int
	Protocol string
}

type TargetList struct {
	v sync.Map
}

func NewIpPortProtocolList() *TargetList {
	return &TargetList{
		v: sync.Map{},
	}
}

func (i *TargetList) Add(ip string, port int, protocol string) {
	v, ok := i.v.Load(ip)
	if !ok {
		i.v.Store(ip, []*PortProtocol{
			{
				Port:     port,
				Protocol: protocol,
			},
		})
	} else {
		d := v.([]*PortProtocol)
		d = append(d, &PortProtocol{
			Port:     port,
			Protocol: protocol,
		})
		i.v.Store(ip, d)
	}
}

func (i *TargetList) GetPortProtocolsByIp(ip string) []*PortProtocol {
	v, ok := i.v.Load(ip)
	if !ok {
		return nil
	}
	return v.([]*PortProtocol)
}

func (i *TargetList) IpCount() int {
	var ipLen int
	i.v.Range(func(key, value interface{}) bool {
		ipLen++
		return true
	})
	return ipLen
}

func (i *TargetList) GetPortCountByIp(ip string) int {
	v, ok := i.v.Load(ip)
	if !ok {
		return 0
	} else {
		return len(v.([]*PortProtocol))
	}
}

func (i *TargetList) GetIpPorts() []*IpPortList {
	var ipPortList []*IpPortList
	i.v.Range(func(key, value interface{}) bool {
		ip := key.(string)
		ipPortList = append(ipPortList, &IpPortList{
			IP:    ip,
			Ports: value.([]*PortProtocol),
		})
		return true
	})
	return ipPortList
}

func (i *TargetList) GetIpPortProtocols() []*IpPortProtocol {
	var ipPortProtocolList []*IpPortProtocol
	i.v.Range(func(key, value interface{}) bool {
		ip := key.(string)
		for _, port := range value.([]*PortProtocol) {
			ipPortProtocolList = append(ipPortProtocolList, &IpPortProtocol{
				IP:       ip,
				Port:     port.Port,
				Protocol: port.Protocol,
			})
		}
		return true
	})
	return ipPortProtocolList
}

type Application struct {
	SC             string
	PocId          string
	PocTags        string
	FingerMatch    bool
	FingerFile     string
	PocFile        string
	NoPing         bool
	FullScan       bool
	SshKey         string
	Verbose        bool
	FofaQuery      string
	FofaSize       int
	FofaKey        string
	ScanRandom     bool
	HttpProxy      string
	Socks5Proxy    string
	Port           string
	Target         string
	TargetUrl      string
	TargetFile     string
	OutputFileName string
	WorkPoolNum    int
	NoVulScan      bool
	Report         bool // 是否输出漏洞报告
	DirDictFile    string
	NoDirScan      bool
	Vul            *AssetsVuls // 扫描过程产生的所有数据

	TLSHandshakeTimeout time.Duration
	WebScanTimeout      time.Duration
	PortScanTimeout     time.Duration
	ICMPTimeOut         time.Duration
}

var application *Application
