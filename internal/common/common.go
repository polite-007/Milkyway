package common

import (
	"bytes"
	"fmt"
	"github.com/jung-kurt/gofpdf"
	"github.com/polite007/Milkyway/static"
	"io"
	"net/url"
	"sync"
	"time"
)

type Resps struct {
	Url        *url.URL
	Title      string
	Body       string
	Header     map[string][]string
	Server     string
	StatusCode int
	FavHash    string
	Cms        string
	Tags       []string
}

// 存放一些通用结构体

// 漏洞结构体
type AssetsVuls struct {
	WebList     []*Resps
	IpPortList  []*IpPortProtocol
	ProtocolVul []*ProtocolVul
	WebVul      []*WebVul
}

func (i *AssetsVuls) AddProtocolVul(ip string, port int, protocol string, message string) {
	i.ProtocolVul = append(i.ProtocolVul, &ProtocolVul{
		IP:       ip,
		Port:     port,
		Protocol: protocol,
		Message:  message,
	})
}

func (i *AssetsVuls) AddWebVul(vulUrl, vulName, des, recovery, level string) {
	i.WebVul = append(i.WebVul, &WebVul{
		VulUrl:      vulUrl,
		VulName:     vulName,
		Description: des,
		Level:       level,
		Recovery:    recovery,
	})
}

type ProtocolVul struct {
	IP       string
	Port     int
	Protocol string
	Message  string
}

type WebVul struct {
	VulUrl      string
	VulName     string
	Level       string // 漏洞等级
	Description string // 漏洞描述
	Recovery    string // 漏洞修复意见
}

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

// 生成 PDF 报告
func (i *AssetsVuls) GenerateReport() {
	// 创建 PDF 实例
	pdf := gofpdf.New("P", "mm", "A4", "")

	// 从嵌入文件系统中读取字体文件
	fontFile, err := static.EmbedFS.Open("ttf/STFANGSO.TTF")
	if err != nil {
		fmt.Println("Error opening embedded font file:", err)
		return
	}
	defer fontFile.Close()

	fontData, err := io.ReadAll(fontFile)
	if err != nil {
		fmt.Println("Error reading embedded font file:", err)
		return
	}

	// 添加支持中文的字体
	pdf.AddUTF8FontFromBytes("simsun", "", fontData)
	pdf.AddUTF8FontFromBytes("simsun", "B", fontData)
	pdf.SetFont("simsun", "", 12)

	// 添加封面
	pdf.AddPage()
	// 添加 logo
	logoFile, err := static.EmbedFS.Open("img/logo.png")
	if err == nil {
		defer logoFile.Close()
		logoData, err := io.ReadAll(logoFile)
		if err == nil {
			pdf.RegisterImageOptionsReader("logo", gofpdf.ImageOptions{ImageType: "PNG", ReadDpi: true}, io.NopCloser(bytes.NewReader(logoData)))
			pdf.ImageOptions("logo", 15, 15, 30, 0, false, gofpdf.ImageOptions{ImageType: "PNG", ReadDpi: true}, 0, "")
		}
	}
	pdf.Ln(60)
	pdf.SetFont("simsun", "B", 40)
	pdf.SetTextColor(0, 0, 0)
	pdf.SetFillColor(230, 230, 230)
	pdf.CellFormat(0, 30, "简易渗透测试报告", "0", 0, "C", true, 0, "")
	pdf.Ln(30)
	pdf.SetFont("simsun", "", 18)
	pdf.CellFormat(0, 10, "By:Milkyway", "0", 0, "C", false, 0, "")
	pdf.Ln(130)
	pdf.SetFont("simsun", "", 18)
	pdf.CellFormat(0, 10, fmt.Sprintf("报告生成时间: %s", time.Now().Format("2006-01-02 15:04:05")), "0", 0, "C", false, 0, "")

	// 添加正文页
	pdf.AddPage()
	pdf.SetFont("simsun", "B", 16)
	pdf.Cell(40, 10, "资产成果")
	pdf.Ln(20)

	// 写入 IpPortList 信息
	pdf.SetFont("simsun", "B", 14)
	pdf.CellFormat(40, 10, "IP 端口列表", "B", 0, "L", false, 0, "")
	pdf.Ln(10)
	pdf.SetFont("simsun", "", 12)
	pdf.SetDrawColor(150, 150, 150)
	pdf.SetFillColor(240, 240, 240)
	// 表头
	pdf.CellFormat(60, 10, "IP", "1", 0, "C", true, 0, "")
	pdf.CellFormat(60, 10, "端口", "1", 0, "C", true, 0, "")
	pdf.CellFormat(60, 10, "协议", "1", 0, "C", true, 0, "")
	pdf.Ln(10)
	for _, ipPort := range i.IpPortList {
		pdf.CellFormat(60, 10, ipPort.IP, "1", 0, "L", false, 0, "")
		pdf.CellFormat(60, 10, fmt.Sprintf("%d", ipPort.Port), "1", 0, "L", false, 0, "")
		pdf.CellFormat(60, 10, ipPort.Protocol, "1", 0, "L", false, 0, "")
		pdf.Ln(10)
	}
	pdf.Ln(20)

	// 写入 WebList 信息
	pdf.SetFont("simsun", "B", 14)
	pdf.CellFormat(40, 10, "Web 列表", "B", 0, "L", false, 0, "")
	pdf.Ln(10)
	pdf.SetFont("simsun", "", 12)
	// 表头
	pdf.CellFormat(47.5, 10, "URL", "1", 0, "C", true, 0, "")
	pdf.CellFormat(47.5, 10, "标题", "1", 0, "C", true, 0, "")
	//pdf.CellFormat(47.5, 10, "服务器", "1", 0, "C", true, 0, "")
	pdf.CellFormat(47.5, 10, "状态码", "1", 0, "C", true, 0, "")
	pdf.CellFormat(47.5, 10, "备注", "1", 0, "C", true, 0, "")
	pdf.Ln(10)

	for _, resp := range i.WebList {
		title := resp.Title
		if title == "" {
			title = "无标题"
		}
		x := pdf.GetX()
		y := pdf.GetY()

		pdf.SetXY(x, y)
		pdf.MultiCell(47.5, 10, resp.Url.String(), "1", "L", false)

		pdf.SetXY(x+47.5, y)
		pdf.MultiCell(47.5, 10, title, "1", "L", false)

		//pdf.SetXY(x+47.5*2, y)
		//pdf.MultiCell(47.5, 10, resp.Server, "1", "L", false)

		pdf.SetXY(x+47.5*2, y)
		pdf.MultiCell(47.5, 10, fmt.Sprintf("%d", resp.StatusCode), "1", "L", false)

		pdf.SetXY(x+47.5*3, y)
		pdf.MultiCell(47.5, 10, resp.Cms, "1", "L", false)
	}
	pdf.Ln(20)

	// 写入 Vul 信息
	pdf.AddPage()
	pdf.SetFont("simsun", "B", 10)
	pdf.Cell(40, 10, "漏洞成果")
	pdf.Ln(20)

	// 写入 ProtocolVul 信息
	pdf.CellFormat(40, 10, "协议漏洞", "B", 0, "L", false, 0, "")
	pdf.Ln(10)
	// 表头
	pdf.CellFormat(47.5, 10, "IP", "1", 0, "C", true, 0, "")
	pdf.CellFormat(47.5, 10, "端口", "1", 0, "C", true, 0, "")
	pdf.CellFormat(47.5, 10, "协议", "1", 0, "C", true, 0, "")
	pdf.CellFormat(47.5, 10, "内容", "1", 0, "C", true, 0, "")
	pdf.Ln(10)
	for _, protocolVul := range i.ProtocolVul {
		x := pdf.GetX()
		y := pdf.GetY()

		pdf.SetXY(x, y)
		pdf.MultiCell(47.5, 10, protocolVul.IP, "1", "L", false)
		pdf.SetXY(x+47.5, y)
		pdf.MultiCell(47.5, 10, fmt.Sprintf("%d", protocolVul.Port), "1", "L", false)
		pdf.SetXY(x+47.5*2, y)
		pdf.MultiCell(47.5, 10, protocolVul.Protocol, "1", "L", false)
		pdf.SetXY(x+47.5*3, y)
		pdf.MultiCell(47.5, 10, protocolVul.Message, "1", "L", false)
	}
	pdf.Ln(20)

	// 写入 WebVul 信息
	pdf.CellFormat(40, 10, "Web 漏洞", "B", 0, "L", false, 0, "")
	pdf.Ln(10)
	// 表头
	pdf.CellFormat(60, 10, "漏洞名称", "1", 0, "C", true, 0, "")
	pdf.CellFormat(60, 10, "漏洞地址", "1", 0, "C", true, 0, "")
	pdf.CellFormat(60, 10, "漏洞等级", "1", 0, "C", true, 0, "")
	pdf.Ln(10)
	for _, webVul := range i.WebVul {
		// 第一行：漏洞名称、漏洞地址、漏洞等级
		x := pdf.GetX()
		y := pdf.GetY()
		pdf.SetXY(x, y)
		pdf.MultiCell(60, 10, webVul.VulName, "1", "L", false)
		pdf.SetXY(x+60, y)
		pdf.MultiCell(60, 10, webVul.VulUrl, "1", "L", false)
		pdf.SetXY(x+60*2, y)
		pdf.MultiCell(60, 10, webVul.Level, "1", "L", false)
		// 第二行：漏洞描述
		pdf.MultiCell(180, 10, "描述: "+webVul.Description, "1", "L", false)
		// 第三行：修复措施
		//pdf.MultiCell(180, 10, "修复措施: "+webVul.Recovery, "1", "L", false)
		pdf.Ln(10)
	}

	// 保存 PDF 文件
	err = pdf.OutputFileAndClose(fmt.Sprintf("%d.pdf", time.Now().Unix()))
	if err == nil {
		fmt.Println("PDF report generated successfully!")
	}
}
