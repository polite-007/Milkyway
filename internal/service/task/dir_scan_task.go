package task

import (
	"fmt"
	"github.com/polite007/Milkyway/internal/config"
	"github.com/polite007/Milkyway/internal/pkg/httpx"
	"github.com/polite007/Milkyway/internal/pkg/web_finger"
	"github.com/polite007/Milkyway/pkg/color"
	"github.com/polite007/Milkyway/pkg/logger"
)

func newDirScanTask(targetList []*config.DirScanTaskPayload, dirList []string) ([]*config.DirScanTaskResult, error) {
	NewPool := NewWorkPool(config.Get().WorkPoolNum)
	NewPool.Start()

	type HostPath struct {
		host string
		path string
	}

	f := func(args any) (any, error) {
		p, ok := args.(config.DirScanTaskPayload)
		if !ok {
			return nil, config.GetErrors().ErrAssertion
		}

		isAlive, err := httpx.Get(p.GetHost(), nil, p.Path)
		if err == nil && isAlive.StatusCode == 200 {
			o := config.DirScanTaskResult{
				IP:   p.IP,
				Port: p.Port,
				Url:  p.Url,
			}

			resp, err := httpx.HandleResponse(isAlive)
			if err != nil {
				return nil, config.GetErrors().ErrTaskFailed
			}

			o.ResPs = resp
		}
		return nil, config.GetErrors().ErrTaskFailed
	}

	go func() {
		for _, dir := range dirList {
			for _, targetUrl := range targetList {
				NewPool.Wg.Add(1)
				targetUrl.Path = dir
				NewPool.TaskQueue <- newTask(targetUrl, f)
			}
		}
		close(NewPool.TaskQueue) // 关闭任务队列
		NewPool.Wg.Wait()        // 等待消费者执行完全部任务
		close(NewPool.Result)    // 关闭结果队列
	}()

	var result []*config.DirScanTaskResult

	for res := range NewPool.Result {
		if res == nil {
			continue
		}
		r := res.(*config.DirScanTaskResult)
		rt := r.ResPs

		// 这里待商榷，为什么这里写25，防止一些空数据, 但25也不是很对劲
		if len(rt.Body) < 25 {
			continue
		}

		var logOut string
		rt.Cms, rt.Tags = web_finger.WebFinger(rt)
		if rt.Cms == "" {
			logOut = fmt.Sprintf("[%s] %-25v len:%d title:%s header: %s",
				color.Green(rt.StatusCode),
				rt.Url,
				len(rt.Body),
				color.Green(rt.Title),
				color.Green(rt.Server),
			)
		} else {
			logOut = fmt.Sprintf("[%s] %-25v len:%d title:%s header: %s cms: %s",
				color.Green(rt.StatusCode),
				rt.Url,
				len(rt.Body),
				color.Green(rt.Title),
				color.Green(rt.Server),
				color.Red(rt.Cms),
			)
		}

		logger.OutLog(logOut)
		result = append(result, r)
	}
	return result, nil
}
