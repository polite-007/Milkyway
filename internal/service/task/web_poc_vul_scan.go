package task

import (
	"fmt"
	config "github.com/polite007/Milkyway/internal/config"

	"github.com/polite007/Milkyway/pkg/color"
	"github.com/polite007/Milkyway/pkg/logger"
)

// newWebPocVulScan 下发url+poc的漏洞扫描任务
func newWebPocVulScan(pocTask []*config.WebPocVulScanPayload) error {
	NewPool := NewWorkPool(config.Get().WorkPoolNum)
	NewPool.Start()

	f := func(args any) (any, error) {
		p, ok := args.(*config.WebPocVulScanPayload)
		if !ok {
			return nil, config.GetErrors().ErrAssertion
		}
		res, _ := p.Poc.Execute(p.TargetUrl, nil)
		if res != nil {
			if res.Matched || res.Extracted {
				result := fmt.Sprintf("[*] %s %s level:%s id: %s\n", p.TargetUrl, color.Red(p.Poc.Info.Name), p.Poc.Info.Severity, p.Poc.Id)
				config.GetAssetsResult().AddWebPocVul(p)
				logger.OutLog(result)
			}
		}
		return nil, config.GetErrors().ErrTaskFailed
	}

	go func() {
		for _, poc := range pocTask {
			NewPool.Wg.Add(1)
			NewPool.TaskQueue <- newTask(poc, f)
		}
		close(NewPool.TaskQueue) // 关闭任务队列
		NewPool.Wg.Wait()        // 等待消费者执行完全部任务
		close(NewPool.Result)    // 关闭结果队列
	}()
	for range NewPool.Result {
	}
	return nil
}
