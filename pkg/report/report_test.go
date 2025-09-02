package report

import (
	"github.com/polite007/Milkyway/internal/config"
	"net/url"
	"testing"
)

func TestGenerateReport(t *testing.T) {
	// 创建测试数据
	result := &config.AssetsResult{
		IpActiveList: []string{
			"192.168.1.1",
			"192.168.1.2",
			"192.168.1.3",
		},
		IpPortList: []*config.IpPortProtocol{
			{
				IP:       "192.168.1.1",
				Port:     80,
				Protocol: "http",
			},
			{
				IP:       "192.168.1.1",
				Port:     443,
				Protocol: "https",
			},
			{
				IP:       "192.168.1.2",
				Port:     8080,
				Protocol: "http",
			},
			{
				IP:       "192.168.1.2",
				Port:     8443,
				Protocol: "https",
			},
			{
				IP:       "192.168.1.3",
				Port:     22,
				Protocol: "ssh",
			},
		},
		WebList: []*config.Resps{
			{
				Url: &url.URL{
					Scheme: "http",
					Host:   "192.168.1.1:80",
				},
				Title:      "测试网站1",
				Cms:        "WordPress",
				Body:       "测试内容1",
				StatusCode: 200,
			},
			{
				Url: &url.URL{
					Scheme: "https",
					Host:   "192.168.1.1:443",
				},
				Title:      "测试网站1安全版",
				Cms:        "WordPress",
				Body:       "测试内容1安全版",
				StatusCode: 200,
			},
			{
				Url: &url.URL{
					Scheme: "http",
					Host:   "192.168.1.2:8080",
				},
				Title:      "测试网站2",
				Cms:        "Drupal",
				Body:       "测试内容2",
				StatusCode: 404,
			},
			{
				Url: &url.URL{
					Scheme: "https",
					Host:   "192.168.1.2:8443",
				},
				Title:      "测试网站2安全版",
				Cms:        "Drupal",
				Body:       "测试内容2安全版",
				StatusCode: 500,
			},
		},
		ProtocolVul: []*config.ProtocolVul{
			{
				IP:       "192.168.1.1",
				Port:     80,
				Protocol: "http",
				Message:  "发现HTTP服务未启用HTTPS",
			},
			{
				IP:       "192.168.1.2",
				Port:     8080,
				Protocol: "http",
				Message:  "发现HTTP服务未启用HTTPS",
			},
		},
		WebVul: []*config.WebVul{
			{
				VulUrl:      "http://192.168.1.1",
				VulName:     "SQL注入漏洞",
				Level:       "高危",
				Description: "在登录页面发现SQL注入漏洞",
				Recovery:    "建议使用参数化查询",
			},
			{
				VulUrl:      "http://192.168.1.2:8080",
				VulName:     "XSS漏洞",
				Level:       "中危",
				Description: "在评论功能中发现XSS漏洞",
				Recovery:    "建议对用户输入进行过滤",
			},
		},
	}

	// 生成报告
	err := GenerateReport(result)
	if err != nil {
		t.Errorf("生成报告失败: %v", err)
	}
}
