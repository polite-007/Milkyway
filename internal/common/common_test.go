package common

import (
	"fmt"
	"net/url"
	"testing"
)

func Test_Report(t *testing.T) {
	// 示例数据

	webUrl, err := url.Parse("https://example.com")
	if err != nil {
		fmt.Printf("解析 URL 时出错: %v\n", err)
		return
	}

	vul := &AssetsVuls{
		IpPortList: []*IpPortProtocol{
			{IP: "192.168.1.1", Port: 80, Protocol: "HTTP"},
			{IP: "192.168.1.2", Port: 443, Protocol: "HTTPS"},
		},
		WebList: []*Resps{
			{
				Url:        webUrl,
				Title:      "Example Domain",
				Body:       "This is an example domain.",
				Header:     make(map[string][]string),
				Server:     "nginx",
				StatusCode: 200,
				FavHash:    "123456",
				Cms:        "WordPress",
				Tags:       []string{"example", "domain"},
			},
		},
		ProtocolVul: []*ProtocolVul{
			{IP: "192.168.1.1", Port: 80, Protocol: "HTTP", Message: "协议漏洞信息"},
		},
		WebVul: []*WebVul{
			{VulUrl: "https://example.com/vuln", VulName: "Web 漏洞名称"},
		},
	}

	// 生成报告
	vul.GenerateReport()
}
