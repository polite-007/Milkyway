package task

import (
	"github.com/polite007/Milkyway/config"
	"github.com/polite007/Milkyway/internal/service/pact/protocol_vul"
)

// ProtocolVulScan 对ip+port+protocol进行对应的协议漏洞扫描
func NewProtocolVulScan(ipPortList map[string][]*config.PortProtocol) error {
	NewPool := NewWorkPool(config.Get().WorkPoolNum)
	NewPool.Start()

	f := func(args any) (any, error) {
		p, ok := args.(*config.PortProtocol)
		if !ok {
			return nil, config.GetErrors().ErrAssertion
		}
		protocol_vul.ProtocolVulScan(p.IP, p.Port, p.Protocol)
		return nil, config.GetErrors().ErrTaskFailed
	}

	go func() {
		for _, ipInfo := range ipPortList {
			for _, portInfo := range ipInfo {
				if portInfo.Protocol != "" {
					NewPool.Wg.Add(1)
					NewPool.TaskQueue <- NewTask(portInfo, f)
				}
			}
		}
		close(NewPool.TaskQueue) // 关闭任务队列
		NewPool.Wg.Wait()        // 等待消费者执行完全部任务
		close(NewPool.Result)    // 关闭结果队列
	}()
	for range NewPool.Result {
	}
	return nil
}
