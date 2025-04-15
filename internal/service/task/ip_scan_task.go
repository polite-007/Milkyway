package task

import (
	"github.com/polite007/Milkyway/config"
	"github.com/polite007/Milkyway/internal/service/protocol_scan_vul/protocol_scan"
)

// IPScanTask 返回存活的ip列表
func newIPScanTask(ipList []string) ([]string, error) {
	// 自定义消费者的内部函数
	NewPool := NewWorkPool(config.Get().WorkPoolNum)
	NewPool.Start()

	f := func(args any) (any, error) {
		ip, ok := args.(string)
		if !ok {
			return nil, config.GetErrors().ErrAssertion
		}
		isAlive := protocol_scan.ICMPCheck(ip, config.Get().ICMPTimeOut)
		if !isAlive {
			return "", nil
		} else {
			return ip, nil
		}
	}

	go func() {
		for _, ip := range ipList {
			NewPool.Wg.Add(1)
			NewPool.TaskQueue <- newTask(ip, f)
		}
		close(NewPool.TaskQueue) // 关闭任务队列
		NewPool.Wg.Wait()        // 等待消费者执行完全部任务
		close(NewPool.Result)    // 关闭结果队列
	}()

	var result []string
	for res := range NewPool.Result {
		resultSimple := res.(string)
		if resultSimple != "" {
			result = append(result, resultSimple)
		}
	}
	return result, nil
}
