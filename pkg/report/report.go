package report

import (
	"fmt"
	"html/template"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/polite007/Milkyway/config"
)

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
	// HTML模板
	const reportTemplate = `
<!DOCTYPE html>
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

        .theme-switch {
            position: absolute;
            right: 20px;
            background: rgba(255, 255, 255, 0.1);
            border: none;
            border-radius: 50%;
            width: 36px;
            height: 36px;
            cursor: pointer;
            display: flex;
            align-items: center;
            justify-content: center;
            color: white;
            font-size: 18px;
            transition: all 0.3s ease;
            z-index: 1;
        }

        .theme-switch:hover {
            background: rgba(255, 255, 255, 0.2);
            transform: scale(1.1);
        }

        .footer {
            margin-top: 80px;
            padding: 40px 20px;
            text-align: center;
            color: var(--text-color);
            opacity: 0.7;
            position: relative;
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
        }

        .footer-icon:hover {
            opacity: 1;
            transform: translateY(-3px);
        }

        .summary-item {
            background: var(--card-bg);
            box-shadow: var(--card-shadow);
        }

        .ip-card {
            background: var(--card-bg);
            box-shadow: var(--card-shadow);
        }

        .vul-item {
            background: var(--card-bg);
            border-radius: 6px;
            padding: 15px;
            margin-bottom: 8px;
            border-left: 3px solid var(--primary-color);
        }

        .vul-item .vul-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 10px;
        }

        .vul-item .vul-title {
            font-size: 16px;
            font-weight: bold;
            color: var(--text-color);
        }

        .vul-item .vul-url {
            font-size: 14px;
            color: var(--text-color);
            word-break: break-all;
            margin: 5px 0;
            padding: 5px;
            background: var(--card-bg);
            border: 1px solid var(--border-color);
            border-radius: 4px;
        }

        .vul-item .vul-protocol {
            display: inline-block;
            padding: 2px 8px;
            border-radius: 4px;
            font-size: 12px;
            background: var(--primary-color);
            color: white;
            margin-right: 8px;
        }

        .vul-item .vul-description {
            margin: 10px 0;
            color: var(--text-color);
            opacity: 0.9;
        }

        .vul-item .vul-recovery {
            margin-top: 10px;
            padding: 10px;
            background: var(--card-bg);
            border: 1px solid var(--border-color);
            border-radius: 4px;
            font-size: 14px;
        }

        .search-box {
            background: var(--card-bg);
            box-shadow: var(--card-shadow);
        }

        .search-input {
            background: var(--card-bg);
            color: var(--text-color);
            border-color: var(--border-color);
        }

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
        }

        .container {
            max-width: 1400px;
            margin: 0 auto;
            padding: 20px;
        }

        .header {
            text-align: center;
            padding: 40px 0;
            background: linear-gradient(135deg, var(--primary-color), var(--secondary-color));
            color: white;
            border-radius: 12px;
            margin-bottom: 30px;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
            position: relative;
            overflow: hidden;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 20px 40px;
        }

        .header-content {
            text-align: center;
            flex: 1;
        }

        .logo {
            position: absolute;
            left: 40px;
            font-size: 24px;
            font-weight: bold;
        }

        .logo::after {
            content: '';
            position: absolute;
            bottom: 0;
            left: 50%;
            transform: translateX(-50%);
            width: 0;
            height: 2px;
            background: white;
            transition: width 0.3s ease;
        }

        .logo:hover::after {
            width: 80%;
        }

        .summary {
            display: flex;
            justify-content: space-around;
            margin: 20px 0;
            flex-wrap: wrap;
        }

        .summary-item {
            text-align: center;
            padding: 20px;
            background: white;
            border-radius: 8px;
            min-width: 200px;
            margin: 10px;
            box-shadow: 0 2px 4px rgba(0, 0, 0, 0.05);
            transition: transform 0.3s ease;
            display: flex;
            align-items: center;
            gap: 15px;
        }

        .summary-item:hover {
            transform: translateY(-5px);
        }

        .summary-icon {
            font-size: 24px;
            width: 40px;
            height: 40px;
            display: flex;
            align-items: center;
            justify-content: center;
            border-radius: 50%;
            background: var(--card-bg);
        }

        .summary-content {
            text-align: left;
        }

        .summary-number {
            font-size: 24px;
            font-weight: bold;
            margin-bottom: 5px;
        }

        .summary-number.ip {
            color: #007AFF;
        }

        .summary-number.web {
            color: #FF9500;
        }

        .summary-number.vul {
            color: #FF3B30;
        }

        .summary-label {
            color: #666;
            font-size: 14px;
        }

        .ip-grid {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(300px, 1fr));
            gap: 20px;
            margin-top: 20px;
        }

        .ip-card {
            background: white;
            border-radius: 12px;
            padding: 15px;
            box-shadow: 0 2px 4px rgba(0, 0, 0, 0.05);
            transition: all 0.3s ease;
            cursor: pointer;
            position: relative;
            overflow: hidden;
        }

        .ip-card:hover {
            transform: translateY(-5px);
            box-shadow: 0 4px 8px rgba(0, 0, 0, 0.1);
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

        .ip-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 10px;
        }

        .ip-title {
            font-size: 18px;
            font-weight: bold;
        }

        .ip-badge {
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 12px;
            color: white;
        }

        .ip-badge.vul {
            background: var(--vul-high);
        }

        .ip-badge.web {
            background: var(--primary-color);
        }

        .ip-content {
            display: none;
            margin-top: 15px;
            padding-top: 15px;
            border-top: 1px solid var(--border-color);
        }

        .ip-content.active {
            display: block;
        }

        .asset-grid {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(200px, 1fr));
            gap: 10px;
            margin-top: 10px;
        }

        .asset-card {
            background: var(--card-bg);
            border-radius: 12px;
            padding: 15px;
            box-shadow: var(--card-shadow);
            margin-bottom: 15px;
        }

        .asset-ip {
            font-size: 18px;
            font-weight: bold;
            cursor: pointer;
            padding: 5px;
            border-radius: 4px;
            transition: background-color 0.3s;
        }

        .asset-ip:hover {
            background-color: rgba(0, 0, 0, 0.05);
        }

        .asset-ports {
            margin-top: 10px;
            display: flex;
            flex-wrap: wrap;
            gap: 10px;
        }

        .port-item {
            background: var(--card-bg);
            padding: 8px 12px;
            border-radius: 6px;
            border: 1px solid var(--border-color);
            display: flex;
            align-items: center;
            gap: 8px;
        }

        .port-number {
            font-weight: bold;
        }

        .protocol-badge {
            background: var(--primary-color);
            color: white;
            padding: 2px 8px;
            border-radius: 4px;
            font-size: 12px;
        }

        .web-info {
            margin-top: 15px;
            padding-top: 15px;
            border-top: 1px solid var(--border-color);
        }

        .web-url {
            word-break: break-all;
            margin-bottom: 8px;
        }

        .web-title, .web-cms {
            color: var(--text-color);
            opacity: 0.8;
            margin-bottom: 5px;
        }

        .vul-section {
            margin-top: 20px;
            padding-top: 20px;
            border-top: 1px solid var(--border-color);
        }

        .vul-section h3 {
            margin-bottom: 15px;
            color: var(--text-color);
            font-size: 18px;
        }

        .vul-item {
            background: var(--card-bg);
            border-radius: 8px;
            padding: 15px;
            margin-bottom: 15px;
            border-left: 4px solid var(--primary-color);
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
            margin-bottom: 10px;
        }

        .vul-title {
            font-size: 16px;
            font-weight: bold;
            color: var(--text-color);
        }

        .vul-level {
            padding: 4px 8px;
            border-radius: 4px;
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
            margin: 10px 0;
            padding: 8px;
            background: var(--card-bg);
            border: 1px solid var(--border-color);
            border-radius: 4px;
            font-size: 14px;
        }

        .vul-protocol {
            display: inline-block;
            padding: 2px 8px;
            border-radius: 4px;
            font-size: 12px;
            background: var(--primary-color);
            color: white;
            margin: 5px 0;
        }

        .vul-description {
            margin: 10px 0;
            color: var(--text-color);
            opacity: 0.9;
            line-height: 1.6;
        }

        .vul-recovery {
            margin-top: 10px;
            padding: 10px;
            background: var(--card-bg);
            border: 1px solid var(--border-color);
            border-radius: 4px;
            font-size: 14px;
        }

        .web-info-item {
            display: flex;
            align-items: flex-start;
            margin: 8px 0;
            gap: 10px;
        }

        .web-info-label {
            min-width: 80px;
            color: var(--text-color);
            opacity: 0.7;
        }

        .web-info-value {
            flex: 1;
            word-break: break-all;
            color: var(--text-color);
        }

        .status-code {
            display: inline-flex;
            align-items: center;
            padding: 2px 8px;
            border-radius: 4px;
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

        .search-box {
            margin: 20px 0;
            padding: 10px;
            background: white;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0, 0, 0, 0.05);
        }

        .search-input {
            width: 100%;
            padding: 10px;
            border: 1px solid var(--border-color);
            border-radius: 6px;
            font-size: 16px;
            outline: none;
            transition: border-color 0.3s ease;
        }

        .search-input:focus {
            border-color: var(--primary-color);
        }

        .filter-buttons {
            display: flex;
            gap: 10px;
            margin: 10px 0;
        }

        .filter-button {
            padding: 8px 16px;
            border: none;
            border-radius: 6px;
            background: var(--primary-color);
            color: white;
            cursor: pointer;
            transition: all 0.3s ease;
        }

        .filter-button:hover {
            background: var(--secondary-color);
        }

        .filter-button.active {
            background: var(--secondary-color);
        }

        [data-theme="dark"] .vul-item .vul-url {
            background: var(--card-bg);
            border-color: var(--border-color);
        }

        [data-theme="dark"] .vul-item .vul-recovery {
            background: var(--card-bg);
            border-color: var(--border-color);
        }

        [data-theme="dark"] .summary-icon {
            background: var(--card-bg);
            border: 1px solid var(--border-color);
        }

        [data-theme="dark"] .vul-item {
            background: var(--card-bg);
            border-color: var(--border-color);
        }

        [data-theme="dark"] .vul-item .vul-level {
            background: var(--card-bg);
            border-color: var(--border-color);
        }

        [data-theme="dark"] .vul-item .vul-description {
            background: var(--card-bg);
            border-color: var(--border-color);
        }

        [data-theme="dark"] .vul-item .vul-recovery {
            background: var(--card-bg);
            border-color: var(--border-color);
        }

        [data-theme="dark"] .vul-item .vul-url {
            background: var(--card-bg);
            border-color: var(--border-color);
        }

        [data-theme="dark"] .vul-item .vul-protocol {
            background: var(--card-bg);
            border-color: var(--border-color);
        }

        .web-info {
            margin-top: 10px;
            padding: 10px;
            background: var(--card-bg);
            border: 1px solid var(--border-color);
            border-radius: 4px;
            font-size: 14px;
        }

        .web-info-tags {
            display: flex;
            flex-wrap: wrap;
            gap: 5px;
            margin-top: 5px;
        }

        .web-info-tag {
            background: var(--primary-color);
            color: white;
            padding: 2px 8px;
            border-radius: 12px;
            font-size: 12px;
        }

        .web-service {
            margin-bottom: 10px;
        }

        .web-divider {
            margin: 10px 0;
            border: none;
            border-top: 1px solid var(--border-color);
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <a href="https://github.com/polite-007/Milkyway" target="_blank" class="logo" style="text-decoration: none; color: white;">Milkyway</a>
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
            <div class="ip-card" data-ip="{{.IP}}">
                <div class="ip-header" onclick="toggleContent('{{.IP}}')">
                    <div class="ip-title">{{.IP}}</div>
                    {{if .HasVul}}
                    <div class="ip-badge vul">存在漏洞</div>
                    {{else if .HasWeb}}
                    <div class="ip-badge web">Web服务</div>
                    {{else}}
                    <div class="ip-badge other">其他</div>
                    {{end}}
                </div>
                <div class="ip-content" id="content-{{.IP}}" style="display: none;">
                    <div class="asset-ports">
                        {{range .Ports}}
                        <div class="port-item">
                            <span class="port-number">{{.Port}}</span>
                            <span class="protocol-badge">{{.Protocol}}</span>
                        </div>
                        {{end}}
                    </div>
                    {{if .WebInfos}}
                    <div class="web-info">
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
                        <h3>漏洞信息</h3>
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
        // 添加调试日志
        console.log('Script loaded');

        function scrollToSection(sectionId) {
            const section = document.getElementById(sectionId);
            if (section) {
                section.scrollIntoView({ behavior: 'smooth' });
            }
        }

        function toggleTheme() {
            const body = document.body;
            const currentTheme = body.getAttribute('data-theme');
            const newTheme = currentTheme === 'dark' ? 'light' : 'dark';
            body.setAttribute('data-theme', newTheme);
            localStorage.setItem('theme', newTheme);
        }

        // 初始化主题
        const savedTheme = localStorage.getItem('theme') || 'light';
        document.body.setAttribute('data-theme', savedTheme);

        // 切换内容显示/隐藏
        function toggleContent(ip) {
            const content = document.getElementById('content-' + ip);
            if (content) {
                const isHidden = content.style.display === 'none' || !content.style.display;
                content.style.display = isHidden ? 'block' : 'none';
            }
        }

        // 添加错误处理
        window.onerror = function(msg, url, lineNo, columnNo, error) {
            console.error('Error: ' + msg + '\nURL: ' + url + '\nLine: ' + lineNo + '\nColumn: ' + columnNo + '\nError object: ' + JSON.stringify(error));
            return false;
        };
    </script>
</body>
</html>
`

	// 准备模板数据
	type TemplateData struct {
		Timestamp         string
		TotalAssets       int
		TotalVulns        int
		HighRiskVulns     int
		SecurityRiskCount int
		IpList            []struct {
			IP              string
			Type            string
			WebURL          string
			Title           string
			Cms             string
			BodyLength      int
			StatusCode      int
			StatusCodeClass string
			Tags            []string
			Ports           []struct {
				Port     int
				Protocol string
			}
			HasVul bool
			HasWeb bool
			Vulns  []struct {
				Type        string
				Name        string
				Level       string
				Description string
				Recovery    string
				URL         string
				Protocol    string
			}
			WebInfos []struct {
				URL             string
				Title           string
				Cms             string
				BodyLength      int
				StatusCode      int
				StatusCodeClass string
			}
		}
		IpCount  int
		WebCount int
		VulCount int
	}

	// 计算高危漏洞数量
	highRiskCount := 0
	for _, vul := range result.WebVul {
		if vul.Level == "高危" {
			highRiskCount++
		}
	}
	for _, vul := range result.ProtocolVul {
		if strings.Contains(strings.ToLower(vul.Message), "高危") {
			highRiskCount++
		}
	}

	// 计算等保风险数量
	securityRiskCount := 0
	for _, ipPort := range result.IpPortList {
		if ipPort.Port != 80 && ipPort.Port != 443 {
			securityRiskCount++
		}
	}

	data := TemplateData{
		Timestamp:         time.Now().Format("2006-01-02 15:04:05"),
		TotalAssets:       len(result.IpPortList),
		TotalVulns:        len(result.WebVul) + len(result.ProtocolVul),
		HighRiskVulns:     highRiskCount,
		SecurityRiskCount: securityRiskCount,
		IpCount:           len(result.IpActiveList),
		WebCount:          len(result.WebList),
		VulCount:          len(result.ProtocolVul) + len(result.WebVul),
	}

	// 处理IP列表数据
	for _, ip := range result.IpActiveList {
		ipData := struct {
			IP              string
			Type            string
			WebURL          string
			Title           string
			Cms             string
			BodyLength      int
			StatusCode      int
			StatusCodeClass string
			Tags            []string
			Ports           []struct {
				Port     int
				Protocol string
			}
			HasVul bool
			HasWeb bool
			Vulns  []struct {
				Type        string
				Name        string
				Level       string
				Description string
				Recovery    string
				URL         string
				Protocol    string
			}
			WebInfos []struct {
				URL             string
				Title           string
				Cms             string
				BodyLength      int
				StatusCode      int
				StatusCodeClass string
			}
		}{
			IP:   ip,
			Type: "IP",
		}

		// 收集该IP的所有端口
		for _, ipPort := range result.IpPortList {
			if ipPort.IP == ip {
				ipData.Ports = append(ipData.Ports, struct {
					Port     int
					Protocol string
				}{
					Port:     ipPort.Port,
					Protocol: ipPort.Protocol,
				})
				// 检查是否是Web服务
				if ipPort.Protocol == "http" || ipPort.Protocol == "https" {
					ipData.HasWeb = true
					ipData.Type = "Web"
					// 构建完整的 URL
					webURL := fmt.Sprintf("%s://%s:%d", ipPort.Protocol, ip, ipPort.Port)
					fmt.Printf("Debug - Building WebURL: %s\n", webURL)
					ipData.WebURL = webURL
				}
			}
		}

		// 检查是否存在漏洞
		for _, vul := range result.WebVul {
			if strings.Contains(vul.VulUrl, ip) {
				ipData.HasVul = true
				ipData.Vulns = append(ipData.Vulns, struct {
					Type        string
					Name        string
					Level       string
					Description string
					Recovery    string
					URL         string
					Protocol    string
				}{
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
		for _, vul := range result.ProtocolVul {
			if vul.IP == ip {
				ipData.HasVul = true
				ipData.Vulns = append(ipData.Vulns, struct {
					Type        string
					Name        string
					Level       string
					Description string
					Recovery    string
					URL         string
					Protocol    string
				}{
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

		// 添加Web服务信息
		for _, web := range result.WebList {
			webURL := web.Url.String()

			// 移除末尾的斜杠进行比较
			webURL = strings.TrimRight(webURL, "/")

			// 检查 URL 是否包含当前 IP
			if strings.Contains(webURL, ip) {

				// 创建新的 Web 服务信息
				webInfo := struct {
					URL             string
					Title           string
					Cms             string
					BodyLength      int
					StatusCode      int
					StatusCodeClass string
				}{
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

				// 将 Web 信息添加到 IP 数据中
				ipData.WebInfos = append(ipData.WebInfos, webInfo)
			}
		}

		data.IpList = append(data.IpList, ipData)
	}

	// 解析并执行模板
	tmpl, err := template.New("report").Parse(reportTemplate)
	if err != nil {
		return fmt.Errorf("解析模板失败: %v", err)
	}

	if err := tmpl.Execute(file, data); err != nil {
		return fmt.Errorf("执行模板失败: %v", err)
	}

	// 获取绝对路径
	absPath, err := filepath.Abs(reportFile)
	if err != nil {
		return fmt.Errorf("获取报告绝对路径失败: %v", err)
	}

	// 转换为文件URL格式
	fileURL := strings.ReplaceAll(absPath, "\\", "/")
	fmt.Printf("报告已生成: %s\n请复制以下地址到浏览器访问：\n%s\n", absPath, fileURL)
	return nil
}
