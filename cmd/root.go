package cmd

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"time"

	"github.com/polite007/Milkyway/internal/config"
	"github.com/polite007/Milkyway/pkg/report"

	"github.com/polite007/Milkyway/internal/cli"
	"github.com/polite007/Milkyway/internal/service/task"
	"github.com/polite007/Milkyway/pkg/logger"
)

var mainContext context.Context

func Execute() {
	var cancel context.CancelFunc
	mainContext, cancel = context.WithCancel(context.Background())
	defer cancel()
	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, os.Interrupt)
	defer func() {
		signal.Stop(signalChan)
		cancel()
	}()
	go func() {
		select {
		case <-signalChan:
			cancel()
			os.Exit(1)
		case <-mainContext.Done():
		}
	}()
	if err := Run(); err != nil {
		fmt.Println("\n" + err.Error())
	}
}

func Run() error {
	timeStart := time.Now()

	// 解析参数
	if err := cli.ParseArgs(); err != nil {
		return err
	}

	// 解析目标&获取目标
	ipList, urlList, DesignatedPorts, err := cli.ParseTarget()
	if err != nil {
		return err
	}

	// 获取全局options
	options := config.Get()

	// 先获取最终结果的结构体
	result := config.GetAssetsResult()

	// 扫描 ip
	if len(ipList) != 0 {
		ipActiveList, err := task.IpActiveScan(ipList)
		if err != nil {
			return err
		}
		// 添加存活的ip
		result.AddActiveIpList(ipActiveList)

		portScanTaskResult, err := task.PortActiveScan(ipActiveList, cli.ParsePort(options.Port), DesignatedPorts)
		if err != nil {
			return err
		}
		// 添加端口信息 #主要是非http协议
		result.AddPortInfos(portScanTaskResult)

		WebScanTaskResult, err := task.WebActiveScan(config.TransformPToW(portScanTaskResult))
		if err != nil {
			return err
		}
		// 添加web信息
		result.AddIPWebInfos(WebScanTaskResult)
	}

	// 扫描 url
	if len(urlList) != 0 {
		WebList, err := task.WebScanWithDomain(urlList)
		if err != nil {
			return err
		}
		result.AddUrlWebInfos(WebList)
	}

	// 目录扫描
	if !config.Get().NoDirScan {
		WebListTemp, err := task.DirScan(result.GetDirScanTaskPayload())
		if err != nil {
			return err
		}
		result.AddDirScanWebInfos(WebListTemp)
	}

	// 漏洞扫描
	if !config.Get().NoVulScan {
		// 协议
		if err = task.ProtocolVulScan(result.GetProtocolVulScanTaskPayload()); err != nil {
			return err
		}

		// nuclei #里面可能包括协议
		if err = task.WebPocVulScan(result.GetWebPocVulScanPayload()); err != nil {
			return err
		}
	}

	// 等待所有日志写入
	logger.OutLog("---------------Logger&Report----------------\n")
	logger.OutLog(fmt.Sprintf("[*] Output Log to %s\n", logger.LogName))
	logger.OutLog(fmt.Sprintf("[*] Over! CostTime: %s\n", time.Since(timeStart).String()))
	logger.LogWaitGroup.Wait()

	// 导出html报告
	return report.GenerateReport(result)
}
