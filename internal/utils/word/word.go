package word

import (
	"fmt"

	"github.com/polite007/Milkyway/pkg/fileutils"

	"github.com/nguyenthenguyen/docx"
)

// Vulnerability 漏洞结构体
type Vulnerability struct {
	Name        string   // 漏洞名称
	Level       string   // 危险等级
	Description string   // 漏洞描述
	Solution    string   // 解决方案
	References  []string // 参考链接
}

// GenerateVulnerabilityReport 生成漏洞报告Word文档
func GenerateVulnerabilityReport(vulns []Vulnerability, filename string) error {
	// 读取模板文件
	if err := fileutils.GenerateEmptyFile(filename); err != nil {
		return fmt.Errorf("生成Word报告失败: %v", err)
	}
	r, err := docx.ReadDocxFile(filename)
	if err != nil {
		return fmt.Errorf("读取模板文件失败: %v", err)
	}
	defer r.Close()

	// 获取可编辑的文档
	doc := r.Editable()

	// 替换文档内容
	for i, vuln := range vulns {
		// 使用占位符来标识每个漏洞的位置
		placeholder := fmt.Sprintf("{{vuln_%d}}", i+1)

		// 构建漏洞内容
		content := fmt.Sprintf("漏洞名称：%s\n"+
			"危险等级：%s\n"+
			"漏洞描述：%s\n"+
			"解决方案：%s\n",
			vuln.Name, vuln.Level, vuln.Description, vuln.Solution)

		// 如果有参考链接，添加到内容中
		if len(vuln.References) > 0 {
			content += "参考链接：\n"
			for _, ref := range vuln.References {
				content += fmt.Sprintf("- %s\n", ref)
			}
		}

		// 替换占位符
		doc.Replace(placeholder, content, -1)
	}

	// 保存文件
	return doc.WriteToFile(filename)
}
