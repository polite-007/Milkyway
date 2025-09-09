package task

import (
	"fmt"

	"github.com/polite007/Milkyway/internal/config"

	"github.com/polite007/Milkyway/internal/pkg/httpx"
	"github.com/polite007/Milkyway/internal/pkg/web_finger"
	"github.com/polite007/Milkyway/pkg/color"
	"github.com/polite007/Milkyway/pkg/logger"
)

// newWebScanTask
func newWebScanTask(targetList []*config.WebScanTaskPayload) ([]*config.WebScanTaskResult, error) {
	NewPool := NewWorkPool(config.Get().WorkPoolNum)
	NewPool.Start()

	f := func(args any) (any, error) {
		p, ok := args.(*Addr)
		if !ok {
			return nil, config.GetErrors().ErrAssertion
		}

		// 发送http包
		isAlive, err := httpx.Get(fmt.Sprintf("http://%s:%d", p.host, p.port), nil, "/")
		if err == nil && isAlive.StatusCode != 400 {
			resp, err := httpx.HandleResponse(isAlive)
			if err == nil {
				return resp, nil
			}
			return &config.WebScanTaskResult{
				PortProtocol: config.PortProtocol{
					IP:       p.host,
					Port:     p.port,
					Protocol: "http",
					WebInfo:  []*config.Resp{resp},
				},
			}, nil
		}

		// 发送https包
		isAlive, err = httpx.Get(fmt.Sprintf("https://%s:%d", p.host, p.port), nil, "/")
		if err == nil && isAlive.StatusCode != 400 {
			resp, err := httpx.HandleResponse(isAlive)
			if err == nil {
				return resp, nil
			}
			return &config.WebScanTaskResult{
				PortProtocol: config.PortProtocol{
					IP:       p.host,
					Port:     p.port,
					Protocol: "http",
					WebInfo:  []*config.Resp{resp},
				},
			}, nil
		}

		return nil, config.GetErrors().ErrTaskFailed
	}

	go func() {
		for _, ipPortProtocol := range targetList {
			NewPool.Wg.Add(1)
			NewPool.TaskQueue <- newTask(&Addr{
				host: ipPortProtocol.Host,
				port: ipPortProtocol.Port,
			}, f)
		}
		close(NewPool.TaskQueue) // 关闭任务队列
		NewPool.Wg.Wait()        // 等待消费者执行完全部任务
		close(NewPool.Result)    // 关闭结果队列
	}()

	var result []*config.WebScanTaskResult

	for res := range NewPool.Result {
		if res == nil {
			continue
		}

		r := res.(*config.WebScanTaskResult)
		webInfo := r.WebInfo[0]
		webInfo.Cms, webInfo.Tags = web_finger.WebFinger(webInfo)

		var logOut string
		if webInfo.Cms == "" {
			logOut = fmt.Sprintf("[%s] %-25v body_len:%d title:%s header: %s",
				color.Green(webInfo.StatusCode),
				webInfo.Url,
				len(webInfo.Body),
				color.Green(webInfo.Title),
				color.Green(webInfo.Server),
			)
		} else {
			logOut = fmt.Sprintf("[%s] %-25v body_len:%d title:%s header: %s cms: %s",
				color.Green(webInfo.StatusCode),
				webInfo.Url,
				len(webInfo.Body),
				color.Green(webInfo.Title),
				color.Green(webInfo.Server),
				color.Red(webInfo.Cms),
			)
		}
		logger.OutLog(logOut)
		result = append(result, r)
	}

	return result, nil
}
