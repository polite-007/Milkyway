package protocol_scan

import (
	"bytes"
	"fmt"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"net"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

func ICMPCheck(ip string, timeOut time.Duration) bool {
	if isAlive, err := ICMPWithRaw(ip, timeOut); err != nil {
		return iCMPWithPing(ip)
	} else {
		return isAlive
	}
}

func iCMPWithPing(ip string) bool {
	var command *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		command = exec.Command("cmd", "/c", "ping -n 1 -w 1 "+ip+" && echo true || echo false") //ping -c 1 -i 0.5 -t 4 -W 2 -w 5 "+ip+" >/dev/null && echo true || echo false"
	case "darwin":
		command = exec.Command("/bin/bash", "-c", "ping -c 1 -W 1 "+ip+" && echo true || echo false") //ping -c 1 -i 0.5 -t 4 -W 2 -w 5 "+ip+" >/dev/null && echo true || echo false"
	default: //linux
		command = exec.Command("/bin/bash", "-c", "ping -c 1 -w 1 "+ip+" && echo true || echo false") //ping -c 1 -i 0.5 -t 4 -W 2 -w 5 "+ip+" >/dev/null && echo true || echo false"
	}
	outInfo := bytes.Buffer{}
	command.Stdout = &outInfo
	err := command.Start()
	if err != nil {
		return false
	}
	if err = command.Wait(); err != nil {
		return false
	} else {
		if strings.Contains(outInfo.String(), "true") && strings.Count(outInfo.String(), ip) > 2 {
			return true
		} else {
			return false
		}
	}
}

func ICMPWithRaw(ip string, timeout time.Duration) (bool, error) {
	//尝试在本地接口上监听 ICMP 数据包
	conn, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		return false, err
	}
	defer conn.Close()

	// 创建 ICMP Echo 请求
	msg := icmp.Message{
		Type: ipv4.ICMPTypeEcho,
		Code: 0,
		Body: &icmp.Echo{
			ID:   1,
			Seq:  1,
			Data: []byte("Ping Test"),
		},
	}
	msgBytes, err := msg.Marshal(nil)
	if err != nil {
		return false, err
	}

	// 发送请求到目标 IP
	target := &net.IPAddr{IP: net.ParseIP(ip)}
	start := time.Now()
	if _, err := conn.WriteTo(msgBytes, target); err != nil {
		return false, err
	}

	// 设置超时时间
	conn.SetReadDeadline(time.Now().Add(timeout))

	// 读取并解析 ICMP 响应
	reply := make([]byte, 1500)
	n, _, err := conn.ReadFrom(reply)
	if err != nil {
		return false, err // 超时或无响应
	}
	duration := time.Since(start)

	// 检查回应类型
	resp, err := icmp.ParseMessage(1, reply[:n])
	if err != nil {
		return false, err
	}
	if resp.Type == ipv4.ICMPTypeEchoReply {
		fmt.Printf("[*] Alive IP: %s, RTT: %v\n", ip, duration)
		return true, nil
	} else {
		return false, nil
	}
}
