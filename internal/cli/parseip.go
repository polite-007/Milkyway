package cli

import (
	"encoding/binary"
	"fmt"
	"math/bits"
	"net"
	"strconv"
	"strings"
)

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

// 获取CIDR地址块的第一个IP和最后一个IP
func getFirstAndLastIP(cidr string) (net.IP, net.IP, error) {
	// 解析CIDR
	_, network, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid CIDR address: %v", err)
	}

	// 获取网络的第一个IP（即网络地址）
	firstIP := network.IP

	// 获取网络的最后一个IP（即广播地址），通过网络地址与子网掩码的反转进行计算
	// 反转子网掩码并与网络地址进行按位或操作
	mask := network.Mask
	lastIP := make(net.IP, len(firstIP))
	for i := 0; i < len(firstIP); i++ {
		lastIP[i] = firstIP[i] | ^mask[i]
	}

	// 返回第一个IP和最后一个IP的字符串形式
	return firstIP, lastIP, nil
}

// ipRangeToList 将起始和结束 IPv4 地址转换为 IP 列表
func ipRangeToList(startIP, endIP string) ([]string, error) {
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

// ipCIDRToList 将 CIDR 转换为 IP 列表
func ipCIDRToList(cidr string) ([]string, error) {
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, fmt.Errorf("无法解析 CIDR: %s", cidr)
	}

	ip1, _, err := getFirstAndLastIP(cidr)
	if err != nil {
		return nil, err
	}

	startInt, err := ipToUint32(ip1)
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
		// 过滤最后一个地址为 0 或 255 的情况
		if i&0xFF == 0 || i&0xFF == 255 {
			continue
		}
		// 防止无限循环
		if i == ^uint32(0) {
			break
		}
		ipList = append(ipList, uint32ToIP(i).String())
	}

	return ipList, nil
}

func IPPORTToList(str string, designatedPorts map[string][]int) ([]string, error) {
	ip := strings.Split(str, ":")[0]
	portRaw := strings.Split(str, ":")[1]
	port, err := strconv.Atoi(portRaw)
	if err != nil {
		return []string{ip}, nil
	}
	if designatedPorts != nil {
		if portsTemp, ok := designatedPorts[ip]; ok {
			designatedPorts[ip] = append(portsTemp, port)
		} else {
			designatedPorts[ip] = []int{port}
		}
	}
	return []string{ip}, nil
}

// checkIPFormat 判断输入的字符串是否是单个IP地址(0)、CIDR格式(1)、IP范围格式(2), IP+Port格式(3)
func checkIPFormat(str string) (int, error) {
	ip1 := net.ParseIP(str)
	if ip1 != nil {
		return 0, nil // 返回0表示是单个IP地址
	}

	if _, _, err := net.ParseCIDR(str); err == nil {
		return 1, nil
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

	if strings.Contains(str, ":") {
		ip := strings.Split(str, ":")[0]
		if net.ParseIP(ip) != nil {
			return 3, nil
		}
	}

	return -1, fmt.Errorf("无法识别的IP地址格式")
}

// ParseStr 将字符串解析为IP地址列表
func ParseStr(str string, designatedPorts map[string][]int) ([]string, error) {
	res, err := checkIPFormat(str)
	if err != nil {
		fmt.Printf("该字符串无法识别,已跳过: %s\n", str)
		return nil, nil
	}
	switch res {
	case 0:
		return []string{str}, nil
	case 1:
		return ipCIDRToList(str)
	case 2:
		return ipRangeToList(strings.Split(str, "-")[0], strings.Split(str, "-")[1])
	case 3:
		return IPPORTToList(str, designatedPorts)
	default:
		return nil, nil
	}
}
