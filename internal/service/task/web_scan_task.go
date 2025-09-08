package task

import (
	"fmt"

	config2 "github.com/polite007/Milkyway/internal/config"

	"github.com/polite007/Milkyway/internal/pkg/httpx"
	"github.com/polite007/Milkyway/internal/pkg/web_finger"
	"github.com/polite007/Milkyway/pkg/color"
	"github.com/polite007/Milkyway/pkg/logger"
	"github.com/polite007/Milkyway/pkg/strutils"
)

// newWebScanTask
func newWebScanTask(targetList []*config2.IpPortProtocol) ([]*config2.IpPortProtocol, []*config2.Resps, error) {
	NewPool := NewWorkPool(config2.Get().WorkPoolNum)
	NewPool.Start()

	f := func(args any) (any, error) {
		p, ok := args.(*Addr)
		if !ok {
			return nil, config2.GetErrors().ErrAssertion
		}
		isAlive, err := httpx.Get(fmt.Sprintf("http://%s:%d", p.host, p.port), nil, "/")
		if err == nil && isAlive.StatusCode != 400 {
			return httpx.HandleResponse(isAlive)
		}

		isAlive, err = httpx.Get(fmt.Sprintf("https://%s:%d", p.host, p.port), nil, "/")
		if err == nil && isAlive.StatusCode != 400 {
			return httpx.HandleResponse(isAlive)
		}

		return nil, config2.GetErrors().ErrTaskFailed
	}

	var ipPortListNotWeb []*config2.IpPortProtocol
	var ipPortList []*config2.IpPortProtocol
	var result []*config2.Resps

	go func() {
		for _, ipPortProtocol := range targetList {
			if ipPortProtocol.Protocol != "" {
				ipPortListNotWeb = append(ipPortListNotWeb, &config2.IpPortProtocol{
					IP:       ipPortProtocol.IP,
					Port:     ipPortProtocol.Port,
					Protocol: ipPortProtocol.Protocol,
				})
				continue
			}
			NewPool.Wg.Add(1)
			NewPool.TaskQueue <- newTask(&Addr{
				host: ipPortProtocol.IP,
				port: ipPortProtocol.Port,
			}, f)
		}
		close(NewPool.TaskQueue) // 关闭任务队列
		NewPool.Wg.Wait()        // 等待消费者执行完全部任务
		close(NewPool.Result)    // 关闭结果队列
	}()

	for res := range NewPool.Result {
		if res == nil {
			continue
		}
		resultSimple := res.(*config2.Resps)
		ip, port := strutils.SplitHost(resultSimple.Url.Host)
		ipPortList = append(ipPortList, &config2.IpPortProtocol{
			IP:       ip,
			Port:     port,
			Protocol: "http",
		})
		resultSimple.Cms, resultSimple.Tags = web_finger.WebFinger(resultSimple)
		var logOut string
		if resultSimple.Cms == "" {
			logOut = fmt.Sprintf("[%s] %-25v body_len:%d title:%s header: %s",
				color.Green(resultSimple.StatusCode),
				resultSimple.Url,
				len(resultSimple.Body),
				color.Green(resultSimple.Title),
				color.Green(resultSimple.Server),
			)
		} else {
			logOut = fmt.Sprintf("[%s] %-25v body_len:%d title:%s header: %s cms: %s",
				color.Green(resultSimple.StatusCode),
				resultSimple.Url,
				len(resultSimple.Body),
				color.Green(resultSimple.Title),
				color.Green(resultSimple.Server),
				color.Red(resultSimple.Cms),
			)
		}
		logger.OutLog(logOut)
		result = append(result, resultSimple)
	}
	// 合并两个map
	ipPortList = append(ipPortList, ipPortListNotWeb...)

	return ipPortList, result, nil
}
