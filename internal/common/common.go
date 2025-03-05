package common

import "sync"

// 存放一些通用结构体

type IpPortProtocol struct {
	IP       string
	Port     int
	Protocol string
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
