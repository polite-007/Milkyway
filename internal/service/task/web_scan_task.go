package task

import (
	"fmt"
	"github.com/polite007/Milkyway/config"
	"github.com/polite007/Milkyway/internal/service/finger"
	"github.com/polite007/Milkyway/internal/service/httpx"
	"github.com/polite007/Milkyway/internal/utils"
	"github.com/polite007/Milkyway/internal/utils/color"
	"github.com/polite007/Milkyway/pkg/logger"
)

// NewWebScanTask
func NewWebScanTask(ipPortList map[string][]*config.PortProtocol) (map[string][]*config.PortProtocol, []*httpx.Resps, error) {
	NewPool := NewWorkPool(config.Get().WorkPoolNum)
	NewPool.Start()

	f := func(args any) (any, error) {
		p, ok := args.(*Addr)
		if !ok {
			return nil, config.GetErrors().ErrAssertion
		}
		isAlive, err := httpx.Get(fmt.Sprintf("http://%s:%d", p.host, p.port), nil, "/")
		if err == nil && isAlive.StatusCode != 400 {
			return httpx.HandleResponse(isAlive)
		}

		isAlive, err = httpx.Get(fmt.Sprintf("https://%s:%d", p.host, p.port), nil, "/")
		if err == nil && isAlive.StatusCode != 400 {
			return httpx.HandleResponse(isAlive)
		}

		return nil, config.GetErrors().ErrTaskFailed
	}

	ipPortListNew := map[string][]*config.PortProtocol{}
	var result []*httpx.Resps

	go func() {
		for host, ports := range ipPortList {
			for _, port := range ports {
				if port.Protocol != "" {
					ipPortListNew[host] = append(ipPortListNew[host], port)
					continue
				}
				NewPool.Wg.Add(1)
				NewPool.TaskQueue <- NewTask(&Addr{
					host: host,
					port: port.Port,
				}, f)
			}
		}
		close(NewPool.TaskQueue) // 关闭任务队列
		NewPool.Wg.Wait()        // 等待消费者执行完全部任务
		close(NewPool.Result)    // 关闭结果队列
	}()

	for res := range NewPool.Result {
		if res == nil {
			continue
		}
		resultSimple := res.(*httpx.Resps)
		ip, port := utils.SplitHost(resultSimple.Url.Host)
		ipPortListNew[ip] = append(ipPortListNew[ip], &config.PortProtocol{
			IP:       ip,
			Port:     port,
			Protocol: "http",
		})
		resultSimple.Cms, resultSimple.Tags = finger.WebFinger(resultSimple)
		var logOut string
		if resultSimple.Cms == "" {
			logOut = fmt.Sprintf("[%s] %-25v len:%d title:%s header: %s\n",
				color.Green(resultSimple.StatusCode),
				resultSimple.Url,
				len(resultSimple.Body),
				color.Green(resultSimple.Title),
				color.Green(resultSimple.Server),
			)
		} else {
			logOut = fmt.Sprintf("[%s] %-25v len:%d title:%s header: %s cms: %s\n",
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
	ipPortListNew = MergeMaps(ipPortList, ipPortListNew)

	return ipPortListNew, result, nil
}

// MergeMaps 合并两个map,m2存在的会覆盖m1
func MergeMaps(m1, m2 map[string][]*config.PortProtocol) map[string][]*config.PortProtocol {
	result := make(map[string][]*config.PortProtocol)
	for k, v := range m1 {
		result[k] = v
	}
	for k, v := range m2 {
		result[k] = v
	}

	return result
}
