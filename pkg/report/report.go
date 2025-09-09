package report

import (
	"fmt"
	"html/template"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/polite007/Milkyway/internal/config"
)

// ReportData 报告数据结构
type ReportData struct {
	Timestamp         string
	TotalAssets       int
	TotalVulns        int
	HighRiskVulns     int
	SecurityRiskCount int
	IpList            []IPData
}

// IPData IP数据结构
type IPData struct {
	IP       string
	Type     string
	HasVul   bool
	HasWeb   bool
	Ports    []PortInfo
	Vulns    []VulnInfo
	WebInfos []WebInfo
}

// PortInfo 端口信息
type PortInfo struct {
	Port     int
	Protocol string
}

// VulnInfo 漏洞信息
type VulnInfo struct {
	Type        string
	Name        string
	Level       string
	Description string
	Recovery    string
	URL         string
	Protocol    string
}

// WebInfo Web服务信息
type WebInfo struct {
	URL             string
	Title           string
	Cms             string
	BodyLength      int
	StatusCode      int
	StatusCodeClass string
}

// GenerateReport 生成HTML格式的扫描报告
func GenerateReport(result *config.AssetsResult) error {
	// 创建报告目录
	reportDir := "reports"
	if err := os.MkdirAll(reportDir, 0755); err != nil {
		return fmt.Errorf("创建报告目录失败: %v", err)
	}

	// 生成报告文件名
	timestamp := time.Now().Format("20060102_150405")
	reportFile := filepath.Join(reportDir, fmt.Sprintf("scan_report_%s.html", timestamp))

	// 创建报告文件
	file, err := os.Create(reportFile)
	if err != nil {
		return fmt.Errorf("创建报告文件失败: %v", err)
	}
	defer file.Close()

	// 准备报告数据
	data, err := prepareReportData(result)
	if err != nil {
		return fmt.Errorf("准备报告数据失败: %v", err)
	}

	// 解析并执行模板
	tmpl, err := template.New("report").Parse(getReportTemplate())
	if err != nil {
		return fmt.Errorf("解析模板失败: %v", err)
	}

	if err := tmpl.Execute(file, data); err != nil {
		return fmt.Errorf("执行模板失败: %v", err)
	}

	// 输出报告路径
	absPath, err := filepath.Abs(reportFile)
	if err != nil {
		return fmt.Errorf("获取报告绝对路径失败: %v", err)
	}

	fileURL := strings.ReplaceAll(absPath, "\\", "/")
	fmt.Printf("报告已生成, 请复制以下地址到浏览器访问: %s\n", fileURL)
	return nil
}

// prepareReportData 准备报告数据
func prepareReportData(result *config.AssetsResult) (*ReportData, error) {
	// 计算高危漏洞数量
	highRiskCount := calculateHighRiskVulns(result)

	// 计算等保风险数量
	securityRiskCount := calculateSecurityRiskCount(result)

	// 处理IP列表数据
	ipList, err := processIPList(result)
	if err != nil {
		return nil, err
	}

	return &ReportData{
		Timestamp:         time.Now().Format("2006-01-02 15:04:05"),
		TotalAssets:       len(result.IpPortList),
		TotalVulns:        len(result.WebVul) + len(result.ProtocolVul),
		HighRiskVulns:     highRiskCount,
		SecurityRiskCount: securityRiskCount,
		IpList:            ipList,
	}, nil
}

// calculateHighRiskVulns 计算高危漏洞数量
func calculateHighRiskVulns(result *config.AssetsResult) int {
	count := 0
	for _, vul := range result.WebVul {
		if vul.Level == "高危" {
			count++
		}
	}
	for _, vul := range result.ProtocolVul {
		if strings.Contains(strings.ToLower(vul.Message), "高危") {
			count++
		}
	}
	return count
}

// calculateSecurityRiskCount 计算等保风险数量
func calculateSecurityRiskCount(result *config.AssetsResult) int {
	count := 0
	for _, ipPort := range result.IpPortList {
		if ipPort.Port != 80 && ipPort.Port != 443 {
			count++
		}
	}
	return count
}

// processIPList 处理IP列表数据
func processIPList(result *config.AssetsResult) ([]IPData, error) {
	var ipList []IPData

	for _, ip := range result.IpActiveList {
		ipData := IPData{
			IP:   ip,
			Type: "IP",
		}

		// 收集该IP的所有端口
		ipData.Ports = collectPortsForIP(ip, result.IpPortList)

		// 检查Web服务
		ipData.HasWeb = checkWebService(ip, result.IpPortList)
		if ipData.HasWeb {
			ipData.Type = "Web"
		}

		// 收集漏洞信息
		ipData.Vulns = collectVulnsForIP(ip, result)
		ipData.HasVul = len(ipData.Vulns) > 0

		// 收集Web服务信息
		ipData.WebInfos = collectWebInfosForIP(ip, result.WebList)

		ipList = append(ipList, ipData)
	}

	return ipList, nil
}

// collectPortsForIP 收集指定IP的端口信息
func collectPortsForIP(ip string, ipPortList []*config.IpPortProtocol) []PortInfo {
	var ports []PortInfo
	for _, ipPort := range ipPortList {
		if ipPort.IP == ip {
			ports = append(ports, PortInfo{
				Port:     ipPort.Port,
				Protocol: ipPort.Protocol,
			})
		}
	}
	return ports
}

// checkWebService 检查是否有Web服务
func checkWebService(ip string, ipPortList []*config.IpPortProtocol) bool {
	for _, ipPort := range ipPortList {
		if ipPort.IP == ip && (ipPort.Protocol == "http" || ipPort.Protocol == "https") {
			return true
		}
	}
	return false
}

// collectVulnsForIP 收集指定IP的漏洞信息
func collectVulnsForIP(ip string, result *config.AssetsResult) []VulnInfo {
	var vulns []VulnInfo

	// 收集Web漏洞
	for _, vul := range result.WebVul {
		if strings.Contains(vul.VulUrl, ip) {
			vulns = append(vulns, VulnInfo{
				Type:        "Web",
				Name:        vul.VulName,
				Level:       vul.Level,
				Description: vul.Description,
				Recovery:    vul.Recovery,
				URL:         vul.VulUrl,
				Protocol:    "http",
			})
		}
	}

	// 收集协议漏洞
	for _, vul := range result.ProtocolVul {
		if vul.IP == ip {
			vulns = append(vulns, VulnInfo{
				Type:        "Protocol",
				Name:        vul.Protocol,
				Level:       "中危",
				Description: vul.Message,
				Recovery:    "建议关闭不必要的端口或限制访问",
				URL:         fmt.Sprintf("%s://%s:%d", vul.Protocol, vul.IP, vul.Port),
				Protocol:    vul.Protocol,
			})
		}
	}

	return vulns
}

// collectWebInfosForIP 收集指定IP的Web服务信息
func collectWebInfosForIP(ip string, webList []*config.Resp) []WebInfo {
	var webInfos []WebInfo

	for _, web := range webList {
		webURL := web.Url.String()
		webURL = strings.TrimRight(webURL, "/")

		if strings.Contains(webURL, ip) {
			webInfo := WebInfo{
				URL:        webURL,
				Title:      web.Title,
				Cms:        web.Cms,
				BodyLength: len(web.Body),
				StatusCode: web.StatusCode,
			}

			// 设置状态码分类
			if webInfo.StatusCode >= 200 && webInfo.StatusCode < 300 {
				webInfo.StatusCodeClass = "2xx"
			} else if webInfo.StatusCode >= 300 && webInfo.StatusCode < 400 {
				webInfo.StatusCodeClass = "3xx"
			} else if webInfo.StatusCode >= 400 && webInfo.StatusCode < 500 {
				webInfo.StatusCodeClass = "4xx"
			} else if webInfo.StatusCode >= 500 {
				webInfo.StatusCodeClass = "5xx"
			}

			webInfos = append(webInfos, webInfo)
		}
	}

	return webInfos
}

// getReportTemplate 获取报告模板
func getReportTemplate() string {
	return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>安全扫描报告-v1.0</title>
    <style>
        :root {
            --primary-color: #007AFF;
            --secondary-color: #5856D6;
            --background-color: #F5F5F7;
            --text-color: #1D1D1F;
            --border-color: #D2D2D7;
            --vul-high: #FF3B30;
            --vul-medium: #FF9500;
            --vul-low: #34C759;
            --card-bg: white;
            --card-shadow: 0 2px 4px rgba(0, 0, 0, 0.05);
        }

        [data-theme="dark"] {
            --primary-color: #0A84FF;
            --secondary-color: #5E5CE6;
            --background-color: #1C1C1E;
            --text-color: #FFFFFF;
            --border-color: #38383A;
            --card-bg: #2C2C2E;
            --card-shadow: 0 2px 4px rgba(0, 0, 0, 0.2);
        }

        /* 主题切换按钮 */
        .theme-switch {
            position: absolute;
            right: 20px;
            top: 50%;
            transform: translateY(-50%);
            background: rgba(255, 255, 255, 0.2);
            border: none;
            border-radius: 50%;
            width: 40px;
            height: 40px;
            cursor: pointer;
            display: flex;
            align-items: center;
            justify-content: center;
            color: white;
            font-size: 18px;
            transition: all 0.3s ease;
            z-index: 10;
        }

        .theme-switch:hover {
            background: rgba(255, 255, 255, 0.3);
            transform: translateY(-50%) scale(1.1);
        }

        /* 底部样式 */
        .footer {
            margin-top: 60px;
            padding: 40px 20px;
            text-align: center;
            color: var(--text-color);
            opacity: 0.7;
            position: relative;
            min-height: 200px;
            display: flex;
            flex-direction: column;
            justify-content: flex-end;
        }

        .footer::before {
            content: '';
            position: absolute;
            top: 0;
            left: 50%;
            transform: translateX(-50%);
            width: 100px;
            height: 1px;
            background: var(--border-color);
        }

        .footer-icons {
            display: flex;
            justify-content: center;
            gap: 20px;
            margin: 30px 0;
        }

        .footer-icon {
            font-size: 24px;
            color: var(--text-color);
            opacity: 0.7;
            transition: all 0.3s ease;
            text-decoration: none;
        }

        .footer-icon:hover {
            opacity: 1;
            transform: translateY(-3px);
        }

        /* 搜索框样式 */
        .search-box {
            background: var(--card-bg);
            box-shadow: var(--card-shadow);
            border-radius: 8px;
            padding: 20px;
            margin: 20px 0;
        }

        .search-input {
            width: 100%;
            padding: 12px 16px;
            border: 2px solid var(--border-color);
            border-radius: 8px;
            font-size: 16px;
            background: var(--card-bg);
            color: var(--text-color);
            outline: none;
            transition: border-color 0.3s ease;
        }

        .search-input:focus {
            border-color: var(--primary-color);
        }

        .search-input::placeholder {
            color: var(--text-color);
            opacity: 0.6;
        }

        /* 过滤按钮 */
        .filter-buttons {
            display: flex;
            gap: 10px;
            margin-top: 15px;
            flex-wrap: wrap;
        }

        .filter-button {
            padding: 8px 16px;
            border: 2px solid var(--border-color);
            border-radius: 20px;
            background: var(--card-bg);
            color: var(--text-color);
            cursor: pointer;
            transition: all 0.3s ease;
            font-size: 14px;
        }

        .filter-button:hover {
            border-color: var(--primary-color);
            background: var(--primary-color);
            color: white;
        }

        .filter-button.active {
            background: var(--primary-color);
            color: white;
            border-color: var(--primary-color);
        }

        /* 基础样式 */
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
            line-height: 1.6;
            color: var(--text-color);
            background-color: var(--background-color);
            min-height: 100vh;
        }

        .container {
            max-width: 1400px;
            margin: 0 auto;
            padding: 20px;
            min-height: 100vh;
            display: flex;
            flex-direction: column;
        }

        /* 头部样式 */
        .header {
            text-align: center;
            padding: 40px 20px;
            background: linear-gradient(135deg, var(--primary-color), var(--secondary-color));
            color: white;
            border-radius: 12px;
            margin-bottom: 30px;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
            position: relative;
            overflow: hidden;
        }

        .header-content h1 {
            font-size: 2.5rem;
            margin-bottom: 10px;
            font-weight: 700;
        }

        .header-content p {
            font-size: 1.1rem;
            opacity: 0.9;
        }

        .logo {
            position: absolute;
            left: 40px;
            top: 50%;
            transform: translateY(-50%);
            font-size: 24px;
            font-weight: bold;
            text-decoration: none;
            color: white;
            transition: opacity 0.3s ease;
        }

        .logo:hover {
            opacity: 0.8;
        }

        /* 统计概览样式 */
        .summary {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin: 20px 0;
        }

        .summary-item {
            background: var(--card-bg);
            border-radius: 12px;
            padding: 25px;
            box-shadow: var(--card-shadow);
            transition: all 0.3s ease;
            display: flex;
            align-items: center;
            gap: 20px;
        }

        .summary-item:hover {
            transform: translateY(-5px);
            box-shadow: 0 8px 25px rgba(0, 0, 0, 0.1);
        }

        .summary-icon {
            font-size: 32px;
            width: 60px;
            height: 60px;
            display: flex;
            align-items: center;
            justify-content: center;
            border-radius: 50%;
            background: linear-gradient(135deg, var(--primary-color), var(--secondary-color));
            color: white;
        }

        .summary-content {
            flex: 1;
        }

        .summary-content h3 {
            font-size: 14px;
            color: var(--text-color);
            opacity: 0.7;
            margin-bottom: 8px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }

        .summary-content p {
            font-size: 28px;
            font-weight: bold;
            color: var(--text-color);
        }

        .summary-item:nth-child(1) .summary-content p { color: #007AFF; }
        .summary-item:nth-child(2) .summary-content p { color: #FF3B30; }
        .summary-item:nth-child(3) .summary-content p { color: #FF9500; }
        .summary-item:nth-child(4) .summary-content p { color: #34C759; }

        /* IP列表布局 - 改为垂直排列 */
        .ip-grid {
            display: flex;
            flex-direction: column;
            gap: 15px;
            margin-top: 20px;
            flex: 1;
        }

        /* IP卡片样式 - 横杠样式 */
        .ip-card {
            background: var(--card-bg);
            border-radius: 8px;
            box-shadow: var(--card-shadow);
            transition: all 0.3s ease;
            cursor: pointer;
            position: relative;
            overflow: hidden;
            border: 1px solid var(--border-color);
            margin-bottom: 10px;
        }

        .ip-card:hover {
            transform: translateY(-2px);
            box-shadow: 0 4px 15px rgba(0, 0, 0, 0.1);
        }

        .ip-card.has-vul {
            border-left: 4px solid var(--vul-high);
        }

        .ip-card.has-web {
            border-left: 4px solid var(--primary-color);
        }

        .ip-card.other {
            border-left: 4px solid var(--border-color);
        }

        .ip-card.expanded {
            border-color: var(--primary-color);
            box-shadow: 0 4px 20px rgba(0, 122, 255, 0.15);
        }

        /* 卡片头部 - 横杠样式 */
        .ip-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 15px 20px;
            background: var(--card-bg);
            border-radius: 8px;
            position: relative;
            min-height: 60px;
        }

        .ip-header::after {
            content: '▼';
            position: absolute;
            right: 20px;
            color: var(--text-color);
            opacity: 0.5;
            font-size: 12px;
            transition: transform 0.3s ease;
        }

        .ip-card.expanded .ip-header::after {
            transform: rotate(180deg);
        }

        .ip-title {
            font-size: 18px;
            font-weight: bold;
            color: var(--text-color);
            flex: 1;
        }

        .ip-header-info {
            display: flex;
            align-items: center;
            gap: 10px;
        }

        .ip-badge {
            padding: 4px 10px;
            border-radius: 15px;
            font-size: 11px;
            font-weight: bold;
            color: white;
        }

        .ip-badge.vul {
            background: var(--vul-high);
        }

        .ip-badge.web {
            background: var(--primary-color);
        }

        .ip-badge.other {
            background: var(--border-color);
        }

        .ip-stats {
            display: flex;
            gap: 8px;
            align-items: center;
        }

        .ip-stat {
            font-size: 12px;
            color: var(--text-color);
            opacity: 0.7;
            padding: 2px 6px;
            background: rgba(0, 0, 0, 0.05);
            border-radius: 10px;
        }

        [data-theme="dark"] .ip-stat {
            background: rgba(255, 255, 255, 0.1);
        }

        /* 卡片内容 - 默认隐藏 */
        .ip-content {
            display: none;
            padding: 0 20px 20px 20px;
            background: var(--card-bg);
            border-top: 1px solid var(--border-color);
        }

        .ip-content.active {
            display: block;
        }

        /* 内容区域标题样式 */
        .ip-content h4 {
            color: var(--text-color);
            font-size: 16px;
            font-weight: bold;
            margin: 20px 0 15px 0;
            padding-bottom: 8px;
            border-bottom: 2px solid var(--primary-color);
            display: inline-block;
        }

        .ip-content h4:first-child {
            margin-top: 0;
        }

        /* 端口信息样式 */
        .asset-ports {
            margin-top: 15px;
            display: flex;
            flex-wrap: wrap;
            gap: 10px;
        }

        .port-item {
            background: var(--card-bg);
            padding: 10px 15px;
            border-radius: 8px;
            border: 1px solid var(--border-color);
            display: flex;
            align-items: center;
            gap: 10px;
            transition: all 0.3s ease;
        }

        .port-item:hover {
            border-color: var(--primary-color);
            background: rgba(0, 122, 255, 0.05);
        }

        .port-number {
            font-weight: bold;
            color: var(--text-color);
            font-size: 16px;
        }

        .protocol-badge {
            background: var(--primary-color);
            color: white;
            padding: 4px 10px;
            border-radius: 12px;
            font-size: 12px;
            font-weight: bold;
        }

        /* Web信息样式 */
        .web-info {
            margin-top: 20px;
            padding-top: 20px;
            border-top: 1px solid var(--border-color);
        }

        .web-service {
            background: var(--card-bg);
            border-radius: 8px;
            padding: 15px;
            margin-bottom: 15px;
            border: 1px solid var(--border-color);
        }

        .web-info-item {
            display: flex;
            align-items: flex-start;
            margin: 10px 0;
            gap: 15px;
        }

        .web-info-label {
            min-width: 80px;
            color: var(--text-color);
            opacity: 0.7;
            font-weight: 500;
        }

        .web-info-value {
            flex: 1;
            word-break: break-all;
            color: var(--text-color);
        }

        .web-divider {
            margin: 15px 0;
            border: none;
            border-top: 1px solid var(--border-color);
        }

        /* 漏洞信息样式 */
        .vul-section {
            margin-top: 20px;
            padding-top: 20px;
            border-top: 1px solid var(--border-color);
        }

        .vul-section h3 {
            margin-bottom: 15px;
            color: var(--text-color);
            font-size: 18px;
            font-weight: bold;
        }

        .vul-item {
            background: var(--card-bg);
            border-radius: 8px;
            padding: 20px;
            margin-bottom: 15px;
            border-left: 4px solid var(--primary-color);
            box-shadow: var(--card-shadow);
        }

        .vul-item.high {
            border-left-color: var(--vul-high);
        }

        .vul-item.medium {
            border-left-color: var(--vul-medium);
        }

        .vul-item.low {
            border-left-color: var(--vul-low);
        }

        .vul-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 15px;
        }

        .vul-title {
            font-size: 18px;
            font-weight: bold;
            color: var(--text-color);
        }

        .vul-level {
            padding: 6px 12px;
            border-radius: 20px;
            font-size: 12px;
            font-weight: bold;
        }

        .vul-level.high {
            background: var(--vul-high);
            color: white;
        }

        .vul-level.medium {
            background: var(--vul-medium);
            color: white;
        }

        .vul-level.low {
            background: var(--vul-low);
            color: white;
        }

        .vul-url {
            word-break: break-all;
            margin: 15px 0;
            padding: 12px;
            background: var(--card-bg);
            border: 1px solid var(--border-color);
            border-radius: 6px;
            font-size: 14px;
            font-family: monospace;
        }

        .vul-protocol {
            display: inline-block;
            padding: 4px 10px;
            border-radius: 12px;
            font-size: 12px;
            background: var(--primary-color);
            color: white;
            margin: 5px 0;
            font-weight: bold;
        }

        .vul-description {
            margin: 15px 0;
            color: var(--text-color);
            opacity: 0.9;
            line-height: 1.6;
        }

        .vul-recovery {
            margin-top: 15px;
            padding: 15px;
            background: var(--card-bg);
            border: 1px solid var(--border-color);
            border-radius: 6px;
            font-size: 14px;
        }

        .vul-recovery strong {
            color: var(--primary-color);
        }

        /* 状态码样式 */
        .status-code {
            display: inline-flex;
            align-items: center;
            padding: 4px 10px;
            border-radius: 12px;
            font-size: 12px;
            font-weight: bold;
        }

        .status-code-2xx {
            background: #e6f4ea;
            color: #1e7e34;
        }

        .status-code-3xx {
            background: #fff3cd;
            color: #856404;
        }

        .status-code-4xx {
            background: #f8d7da;
            color: #721c24;
        }

        .status-code-5xx {
            background: #f8d7da;
            color: #721c24;
        }

        [data-theme="dark"] .status-code-2xx {
            background: rgba(30, 126, 52, 0.2);
            color: #4caf50;
        }

        [data-theme="dark"] .status-code-3xx {
            background: rgba(133, 100, 4, 0.2);
            color: #ffc107;
        }

        [data-theme="dark"] .status-code-4xx {
            background: rgba(114, 28, 36, 0.2);
            color: #f44336;
        }

        [data-theme="dark"] .status-code-5xx {
            background: rgba(114, 28, 36, 0.2);
            color: #f44336;
        }

        /* 响应式设计 */
        @media (max-width: 768px) {
            .container {
                padding: 10px;
            }
            
            .header {
                padding: 20px 10px;
            }
            
            .header-content h1 {
                font-size: 2rem;
            }
            
            .logo {
                position: static;
                transform: none;
                margin-bottom: 10px;
            }
            
            .summary {
                grid-template-columns: 1fr;
            }
            
            .ip-header {
                padding: 12px 15px;
                flex-direction: column;
                align-items: flex-start;
                gap: 10px;
            }
            
            .ip-header-info {
                width: 100%;
                justify-content: space-between;
            }
            
            .ip-stats {
                flex-wrap: wrap;
                gap: 5px;
            }
            
            .ip-stat {
                font-size: 11px;
                padding: 1px 4px;
            }
            
            .filter-buttons {
                justify-content: center;
            }
            
            .ip-content {
                padding: 0 15px 15px 15px;
            }
            
            .asset-ports {
                flex-direction: column;
                gap: 8px;
            }
            
            .port-item {
                padding: 8px 12px;
            }
        }

    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <a href="https://github.com/polite-007/Milkyway" target="_blank" class="logo">Milkyway</a>
            <div class="header-content">
                <h1>安全扫描报告</h1>
                <p>扫描时间: {{.Timestamp}}</p>
            </div>
            <button class="theme-switch" onclick="toggleTheme()">🌓</button>
        </div>

        <div class="summary">
            <div class="summary-item">
                <div class="summary-icon">🌐</div>
                <div class="summary-content">
                    <h3>资产总数</h3>
                    <p>{{.TotalAssets}}</p>
                </div>
            </div>
            <div class="summary-item">
                <div class="summary-icon">🔍</div>
                <div class="summary-content">
                    <h3>漏洞总数</h3>
                    <p>{{.TotalVulns}}</p>
                </div>
            </div>
            <div class="summary-item">
                <div class="summary-icon">⚠️</div>
                <div class="summary-content">
                    <h3>高危漏洞</h3>
                    <p>{{.HighRiskVulns}}</p>
                </div>
            </div>
            <div class="summary-item">
                <div class="summary-icon">🔒</div>
                <div class="summary-content">
                    <h3>等保风险</h3>
                    <p>{{.SecurityRiskCount}}</p>
                </div>
            </div>
        </div>

        <div class="search-box">
            <input type="text" class="search-input" placeholder="搜索IP地址..." onkeyup="filterIPs(this.value)">
            <div class="filter-buttons">
                <button class="filter-button active" onclick="filterByType('all')">全部</button>
                <button class="filter-button" onclick="filterByType('vul')">存在漏洞</button>
                <button class="filter-button" onclick="filterByType('web')">Web服务</button>
                <button class="filter-button" onclick="filterByType('other')">其他</button>
            </div>
        </div>

        <div class="ip-grid">
            {{range .IpList}}
            <div class="ip-card {{if .HasVul}}has-vul{{else if .HasWeb}}has-web{{else}}other{{end}}" data-ip="{{.IP}}">
                <div class="ip-header" onclick="toggleContent('{{.IP}}')">
                    <div class="ip-title">{{.IP}}</div>
                    <div class="ip-header-info">
                        <div class="ip-stats">
                            {{if .Ports}}
                            <span class="ip-stat">{{len .Ports}}端口</span>
                            {{end}}
                            {{if .WebInfos}}
                            <span class="ip-stat">{{len .WebInfos}}Web</span>
                            {{end}}
                            {{if .Vulns}}
                            <span class="ip-stat">{{len .Vulns}}漏洞</span>
                            {{end}}
                        </div>
                        {{if .HasVul}}
                        <div class="ip-badge vul">存在漏洞</div>
                        {{else if .HasWeb}}
                        <div class="ip-badge web">Web服务</div>
                        {{else}}
                        <div class="ip-badge other">其他</div>
                        {{end}}
                    </div>
                </div>
                <div class="ip-content" id="content-{{.IP}}">
                    {{if .Ports}}
                    <div class="asset-ports">
                        <h4>端口信息</h4>
                        {{range .Ports}}
                        <div class="port-item">
                            <span class="port-number">{{.Port}}</span>
                            <span class="protocol-badge">{{.Protocol}}</span>
                        </div>
                        {{end}}
                    </div>
                    {{end}}
                    {{if .WebInfos}}
                    <div class="web-info">
                        <h4>Web服务信息</h4>
                        {{range .WebInfos}}
                        <div class="web-service">
                            <div class="web-info-item">
                                <span class="web-info-label">URL:</span>
                                <span class="web-info-value">{{.URL}}</span>
                            </div>
                            {{if .Title}}
                            <div class="web-info-item">
                                <span class="web-info-label">标题:</span>
                                <span class="web-info-value">{{.Title}}</span>
                            </div>
                            {{end}}
                            {{if .BodyLength}}
                            <div class="web-info-item">
                                <span class="web-info-label">响应长度:</span>
                                <span class="web-info-value">{{.BodyLength}} bytes</span>
                            </div>
                            {{end}}
                            {{if .StatusCode}}
                            <div class="web-info-item">
                                <span class="web-info-label">状态码:</span>
                                <span class="web-info-value status-code status-code-{{.StatusCodeClass}}">{{.StatusCode}}</span>
                            </div>
                            {{end}}
                            {{if .Cms}}
                            <div class="web-info-item">
                                <span class="web-info-label">CMS:</span>
                                <span class="web-info-value">{{.Cms}}</span>
                            </div>
                            {{end}}
                            <hr class="web-divider">
                        </div>
                        {{end}}
                    </div>
                    {{end}}
                    {{if .Vulns}}
                    <div class="vul-section">
                        <h4>漏洞信息</h4>
                        {{range .Vulns}}
                        <div class="vul-item {{.Level}}">
                            <div class="vul-header">
                                <div class="vul-title">{{.Name}}</div>
                                <div class="vul-level {{.Level}}">{{.Level}}</div>
                            </div>
                            <div class="vul-url">{{.URL}}</div>
                            <div class="vul-protocol">{{.Protocol}}</div>
                            <div class="vul-description">{{.Description}}</div>
                            <div class="vul-recovery">
                                <strong>修复建议：</strong>{{.Recovery}}
                            </div>
                        </div>
                        {{end}}
                    </div>
                    {{end}}
                </div>
            </div>
            {{end}}
        </div>
    </div>

    <div class="footer">
        <div class="footer-icons">
            <a href="https://github.com/polite-007/Milkyway" target="_blank" class="footer-icon">📦</a>
            <a href="https://github.com/polite-007/Milkyway/issues" target="_blank" class="footer-icon">🐛</a>
            <a href="https://github.com/polite-007/Milkyway/stargazers" target="_blank" class="footer-icon">⭐</a>
            <a href="https://github.com/polite-007/Milkyway/network" target="_blank" class="footer-icon">🌐</a>
        </div>
        <p>Powered by Milkyway Security Scanner</p>
    </div>

    <script>
        // 全局变量
        let allIPCards = [];
        let currentFilter = 'all';

        // 页面加载完成后初始化
        document.addEventListener('DOMContentLoaded', function() {
            console.log('页面加载完成');
            
            // 收集所有IP卡片
            allIPCards = Array.from(document.querySelectorAll('.ip-card'));
            console.log('找到IP卡片数量:', allIPCards.length);
            
            // 初始化主题
            initTheme();
            
            // 初始化搜索功能
            initSearch();
            
            // 初始化过滤功能
            initFilter();
        });

        // 初始化主题
        function initTheme() {
            const savedTheme = localStorage.getItem('theme') || 'light';
            document.body.setAttribute('data-theme', savedTheme);
            console.log('主题初始化:', savedTheme);
        }

        // 切换主题
        function toggleTheme() {
            const body = document.body;
            const currentTheme = body.getAttribute('data-theme');
            const newTheme = currentTheme === 'dark' ? 'light' : 'dark';
            
            body.setAttribute('data-theme', newTheme);
            localStorage.setItem('theme', newTheme);
            
            console.log('主题切换:', currentTheme, '->', newTheme);
        }

        // 初始化搜索功能
        function initSearch() {
            const searchInput = document.querySelector('.search-input');
            if (searchInput) {
                searchInput.addEventListener('input', function(e) {
                    filterIPs(e.target.value);
                });
            }
        }

        // 初始化过滤功能
        function initFilter() {
            const filterButtons = document.querySelectorAll('.filter-button');
            filterButtons.forEach(button => {
                button.addEventListener('click', function() {
                    // 移除所有按钮的active类
                    filterButtons.forEach(btn => btn.classList.remove('active'));
                    // 添加当前按钮的active类
                    this.classList.add('active');
                    
                    // 获取过滤类型
                    const filterType = this.textContent.trim();
                    if (filterType === '全部') currentFilter = 'all';
                    else if (filterType === '存在漏洞') currentFilter = 'vul';
                    else if (filterType === 'Web服务') currentFilter = 'web';
                    else if (filterType === '其他') currentFilter = 'other';
                    
                    console.log('过滤类型:', currentFilter);
                    
                    // 应用过滤
                    applyFilter();
                });
            });
        }

        // IP搜索功能
        function filterIPs(searchTerm) {
            console.log('搜索IP:', searchTerm);
            
            // 搜索时关闭所有卡片
            closeAllCards();
            
            if (!searchTerm || searchTerm.trim() === '') {
                // 如果搜索框为空，显示所有卡片
                allIPCards.forEach(card => {
                    card.style.display = 'block';
                });
            } else {
                // 根据搜索词过滤
                const searchLower = searchTerm.toLowerCase().trim();
                allIPCards.forEach(card => {
                    const ip = card.getAttribute('data-ip');
                    if (ip && ip.toLowerCase().includes(searchLower)) {
                        card.style.display = 'block';
                    } else {
                        card.style.display = 'none';
                    }
                });
            }
        }

        // 应用过滤
        function applyFilter() {
            // 过滤时关闭所有卡片
            closeAllCards();
            
            allIPCards.forEach(card => {
                const hasVul = card.classList.contains('has-vul');
                const hasWeb = card.classList.contains('has-web');
                const isOther = card.classList.contains('other');
                
                let shouldShow = false;
                
                switch (currentFilter) {
                    case 'all':
                        shouldShow = true;
                        break;
                    case 'vul':
                        shouldShow = hasVul;
                        break;
                    case 'web':
                        shouldShow = hasWeb;
                        break;
                    case 'other':
                        shouldShow = isOther;
                        break;
                }
                
                if (shouldShow) {
                    card.style.display = 'block';
                } else {
                    card.style.display = 'none';
                }
            });
        }

        // 切换内容显示/隐藏 - 手风琴效果
        function toggleContent(ip) {
            const content = document.getElementById('content-' + ip);
            const card = document.querySelector('[data-ip="' + ip + '"]');
            
            if (content && card) {
                const isHidden = content.style.display === 'none' || !content.style.display;
                
                if (isHidden) {
                    // 先关闭所有其他卡片
                    closeAllCards();
                    
                    // 展开当前卡片
                    content.style.display = 'block';
                    content.classList.add('active');
                    card.classList.add('expanded');
                } else {
                    // 收起当前卡片
                    content.style.display = 'none';
                    content.classList.remove('active');
                    card.classList.remove('expanded');
                }
                
                console.log('切换IP内容显示:', ip, isHidden ? '显示' : '隐藏');
            }
        }

        // 关闭所有卡片
        function closeAllCards() {
            const allCards = document.querySelectorAll('.ip-card');
            const allContents = document.querySelectorAll('.ip-content');
            
            allCards.forEach(card => {
                card.classList.remove('expanded');
            });
            
            allContents.forEach(content => {
                content.style.display = 'none';
                content.classList.remove('active');
            });
        }

        // 错误处理
        window.onerror = function(msg, url, lineNo, columnNo, error) {
            console.error('JavaScript错误:', {
                message: msg,
                url: url,
                line: lineNo,
                column: columnNo,
                error: error
            });
            return false;
        };
    </script>
</body>
</html>`

}
