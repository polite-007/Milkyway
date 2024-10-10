package utils

import (
	"encoding/binary"
	"fmt"
	"math/bits"
	"net"
	"strings"
)

type parseIP struct{}

var ParseIP = &parseIP{}

// ipToUint32 将 IPv4 地址转换为 uint32
func ipToUint32(ip net.IP) (uint32, error) {
	ip = ip.To4()
	if ip == nil {
		return 0, fmt.Errorf("无效的 IPv4 地址: %s", ip.String())
	}
	return binary.BigEndian.Uint32(ip), nil
}

// uint32ToIP 将 uint32 转换回 IPv4 地址
func uint32ToIP(n uint32) net.IP {
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, n)
	return ip
}

// IpRangeToList 将起始和结束 IPv4 地址转换为 IP 列表
func IpRangeToList(startIP, endIP string) ([]string, error) {
	start := net.ParseIP(startIP)
	if start == nil {
		return nil, fmt.Errorf("无法解析起始 IP 地址: %s", startIP)
	}
	end := net.ParseIP(endIP)
	if end == nil {
		return nil, fmt.Errorf("无法解析结束 IP 地址: %s", endIP)
	}

	startInt, err := ipToUint32(start)
	if err != nil {
		return nil, err
	}
	endInt, err := ipToUint32(end)
	if err != nil {
		return nil, err
	}

	if startInt > endInt {
		return nil, fmt.Errorf("起始 IP 地址应小于或等于结束 IP 地址")
	}

	var ipList []string
	for i := startInt; i <= endInt; i++ {
		ip := uint32ToIP(i).String()
		// 防止无限循环
		if i == ^uint32(0) {
			break
		}
		// 过滤最后一个地址为 0 或 255 的情况
		if i&0xFF == 0 || i&0xFF == 255 {
			continue
		}
		ipList = append(ipList, ip)
	}

	return ipList, nil
}

// IpCIDRToList 将 CIDR 转换为 IP 列表
func IpCIDRToList(cidr string) ([]string, error) {
	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, fmt.Errorf("无法解析 CIDR: %s", cidr)
	}

	startInt, err := ipToUint32(ip)
	if err != nil {
		return nil, err
	}

	// 计算结束 IP
	var maskBits int
	for _, bit := range ipnet.Mask {
		maskBits += bits.OnesCount8(bit)
	}
	hostBits := 32 - maskBits
	endInt := startInt + (1 << hostBits) - 1

	var ipList []string
	for i := startInt; i <= endInt; i++ {
		ipList = append(ipList, uint32ToIP(i).String())
		// 防止无限循环
		if i == ^uint32(0) {
			break
		}
	}

	return ipList, nil
}

// JudgeString 判断输入的字符串是否是单个IP地址(1)、CIDR格式(2)、IP范围格式(3)
func JudgeString(str string) (int, error) {
	ip1 := net.ParseIP(str)
	if ip1 != nil {
		return 0, nil // 返回0表示是单个IP地址
	}

	if strings.Contains(str, "/") {
		ip2 := strings.Split(str, "/")[0]
		if net.ParseIP(ip2) != nil {
			return 1, nil // 返回1表示是CIDR格式
		}
	}

	if strings.Contains(str, "-") {
		n := 0 // 判断自增符
		ip3 := strings.Split(str, "-")[0]
		if net.ParseIP(ip3) != nil {
			n++
		}
		ip4 := strings.Split(str, "-")[1]
		if net.ParseIP(ip4) != nil {
			n++
		}
		if n == 2 {
			return 2, nil
		}
	}

	return -1, fmt.Errorf("无法识别的IP地址格式")
}
