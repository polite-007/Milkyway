package cmd

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"time"

	"github.com/polite007/Milkyway/config"
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
		panic(err)
	}
}

func Run() error {
	var (
		ipList          []string // ip列表
		urlList         []string // url列表
		DesignatedPorts map[string][]int
		timeStart       = time.Now() // 任务开始时间
		err             error
	)
	if err = cli.ParseArgs(); err != nil {
		return err
	}
	config.Get().PrintDefaultUsage()
	ipList, urlList, DesignatedPorts, err = cli.ParseTarget()
	if err != nil {
		return err
	}
	if len(ipList) != 0 {
		if config.Get().Result.IpActiveList, err = task.IpActiveScan(ipList); err != nil {
			return err
		}
		if config.Get().Result.IpPortList, err = task.PortActiveScan(config.Get().Result.IpActiveList, cli.ParsePort(config.Get().Port), DesignatedPorts); err != nil {
			return err
		}
		if config.Get().Result.IpPortList, config.Get().Result.WebList, err = task.WebActiveScan(config.Get().Result.IpPortList); err != nil {
			return err
		}
	}
	if len(urlList) != 0 {
		if WebListTemp, err := task.WebScanWithDomain(urlList); err == nil {
			config.Get().Result.WebList = append(config.Get().Result.WebList, WebListTemp...)
		}
	}
	if !config.Get().NoDirScan {
		if WebListTemp, err := task.DirScan(config.Get().Result.WebList); err == nil {
			config.Get().Result.WebList = append(config.Get().Result.WebList, WebListTemp...)
		}
	}
	if !config.Get().NoVulScan {
		if err = task.ProtocolVulScan(config.Get().Result.IpPortList); err != nil {
			return err
		}
		if err = task.WebPocVulScan(config.Get().Result.WebList); err != nil {
			return err
		}
	}
	// 等待所有日志写入
	logger.OutLog(fmt.Sprintf("[*] Output Log to %s\n", logger.LogName))
	logger.OutLog(fmt.Sprintf("[*] Over! CostTime: %s\n", time.Since(timeStart).String()))
	logger.LogWaitGroup.Wait()
	return nil
}
