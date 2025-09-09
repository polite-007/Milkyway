package task

import (
	"github.com/polite007/Milkyway/internal/config"
	"math/rand"
	"time"

	"github.com/polite007/Milkyway/internal/service/protocol/protocol_scan"
)

func TransformBatch(results []*config.PortScanTaskResult) []*config.PortScanTaskResultTwo {
	hostMap := make(map[string][]struct {
		Port     int
		Protocol string
	})

	// 聚合：同一个 Host 合并 Ports
	for _, r := range results {
		hostMap[r.Host] = append(hostMap[r.Host], struct {
			Port     int
			Protocol string
		}{
			Port:     r.Port,
			Protocol: r.Protocol,
		})
	}

	// 转换为目标结构
	var merged []*config.PortScanTaskResultTwo
	for host, ports := range hostMap {
		merged = append(merged, &config.PortScanTaskResultTwo{
			Host:  host,
			Ports: ports,
		})
	}

	return merged
}

func newPortScanTask(ipPortList []*config.PortScanTaskPayload, isRandom bool) ([]*config.PortScanTaskResult, error) {
	NewPool := NewWorkPool(config.Get().WorkPoolNum)
	NewPool.Start()

	f := func(args any) (any, error) {
		p, ok := args.(*Addr)
		if !ok {
			return nil, config.GetErrors().ErrAssertion
		}
		protocol, isAlive := protocol_scan.PortScan(p.host, p.port, config.Get().PortScanTimeout)
		if !isAlive {
			return nil, nil
		} else {
			return &Addr{
				host:     p.host,
				port:     p.port,
				protocol: protocol,
			}, nil
		}
	}

	var tasks []*Addr

	for _, ipPort := range ipPortList {
		for _, port := range ipPort.Ports {
			tasks = append(tasks, &Addr{
				host: ipPort.IP,
				port: port,
			})
		}
	}

	if isRandom {
		// 2. 打乱任务切片
		rand.Seed(time.Now().UnixNano())
		rand.Shuffle(len(tasks), func(i, j int) {
			tasks[i], tasks[j] = tasks[j], tasks[i]
		})
	}

	go func() {
		for _, task := range tasks {
			NewPool.Wg.Add(1)
			NewPool.TaskQueue <- newTask(&Addr{
				host: task.host,
				port: task.port,
			}, f)
		}
		close(NewPool.TaskQueue) // 关闭任务队列
		NewPool.Wg.Wait()        // 等待消费者执行完全部任务
		close(NewPool.Result)    // 关闭结果队列
	}()

	result := make([]*config.PortScanTaskResult, 0, len(NewPool.Result))

	for res := range NewPool.Result {
		if res == nil {
			continue
		}
		resultSimple := res.(*Addr)
		result = append(result, &config.PortScanTaskResult{
			Host:     resultSimple.host,
			Port:     resultSimple.port,
			Protocol: resultSimple.protocol,
		})
	}
	return result, nil
}
