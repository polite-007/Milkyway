package config

// Vulnerability 漏洞结构体
type Vulnerability struct {
	Name        string   // 漏洞名称
	Level       string   // 危险等级
	Description string   // 漏洞描述
	Solution    string   // 解决方案
	References  []string // 参考链接
}
