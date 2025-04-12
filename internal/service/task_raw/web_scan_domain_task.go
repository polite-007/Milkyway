package task_raw

import (
	"fmt"
	"github.com/polite007/Milkyway/internal/common"

	"github.com/polite007/Milkyway/config"
	"github.com/polite007/Milkyway/internal/utils/finger"
	"github.com/polite007/Milkyway/internal/utils/httpx"
	"github.com/polite007/Milkyway/pkg/color"
	"github.com/polite007/Milkyway/pkg/logger"
)

// newWebScanWithDomainTask
func newWebScanWithDomainTask(targetUrls []string) ([]*common.Resps, error) {
	NewPool := NewWorkPool(config.Get().WorkPoolNum)
	NewPool.Start()

	f := func(args any) (any, error) {
		p, ok := args.(string)
		if !ok {
			return nil, config.GetErrors().ErrAssertion
		}
		if p[len(p)-1] == '/' {
			p = p[:len(p)-2]
		}
		isAlive, err := httpx.Get(p, nil, "/")
		if err == nil && isAlive.StatusCode != 400 {
			return httpx.HandleResponse(isAlive)
		}

		isAlive, err = httpx.Get(p, nil, "/")
		if err == nil && isAlive.StatusCode != 400 {
			return httpx.HandleResponse(isAlive)
		}

		return nil, config.GetErrors().ErrTaskFailed
	}

	go func() {
		for _, targetUrl := range targetUrls {
			NewPool.Wg.Add(1)
			NewPool.TaskQueue <- newTask(targetUrl, f)
		}
		close(NewPool.TaskQueue) // 关闭任务队列
		NewPool.Wg.Wait()        // 等待消费者执行完全部任务
		close(NewPool.Result)    // 关闭结果队列
	}()

	var result []*common.Resps
	for res := range NewPool.Result {
		if res == nil {
			continue
		}
		resultSimple := res.(*common.Resps)
		var logOut string
		resultSimple.Cms, resultSimple.Tags = finger.WebFinger(resultSimple)
		if resultSimple.Cms == "" {
			logOut = fmt.Sprintf("[%s] %-25v len:%d title:%s header: %s",
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
	return result, nil
}
