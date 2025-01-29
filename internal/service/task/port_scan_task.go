package task

import (
	"github.com/polite007/Milkyway/config"
	"github.com/polite007/Milkyway/internal/service/pact"
	"math/rand"
	"time"
)

// NewPortScanTask 返回存活的端口和对应的协议
func NewPortScanTask(ipPortList map[string][]int) (map[string][]*config.PortProtocol, error) {
	var PortScanTask []*Addr
	NewPool := NewWorkPool(config.Get().WorkPoolNum)
	NewPool.Start()

	f := func(args any) (any, error) {
		p, ok := args.(*Addr)
		if !ok {
			return nil, config.GetErrors().ErrAssertion
		}
		protocol, isAlive := pact.PortScan(p.host, p.port, config.PortScanTimeout)
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
	for host, ports := range ipPortList {
		for _, port := range ports {
			PortScanTask = append(PortScanTask, &Addr{
				host: host,
				port: port,
			})
		}
	}
	rand.Seed(time.Now().UnixNano())
	rand.Shuffle(len(PortScanTask), func(i, j int) {
		PortScanTask[i], PortScanTask[j] = PortScanTask[j], PortScanTask[i]
	})
	go func() {
		for _, p := range PortScanTask {
			NewPool.Wg.Add(1)
			NewPool.TaskQueue <- NewTask(p, f)
		}
		close(NewPool.TaskQueue) // 关闭任务队列
		NewPool.Wg.Wait()        // 等待消费者执行完全部任务
		close(NewPool.Result)    // 关闭结果队列
	}()

	result := map[string][]*config.PortProtocol{}
	for res := range NewPool.Result {
		if res == nil {
			continue
		}
		resultSimple := res.(*Addr)
		result[resultSimple.host] = append(result[resultSimple.host], &config.PortProtocol{
			IP:       resultSimple.host,
			Port:     resultSimple.port,
			Protocol: resultSimple.protocol,
		})
	}
	return result, nil
}

func NewPortScanTaskRandom(ipPortList map[string][]int) (map[string][]*config.PortProtocol, error) {
	NewPool := NewWorkPool(config.Get().WorkPoolNum)
	NewPool.Start()

	f := func(args any) (any, error) {
		p, ok := args.(*Addr)
		if !ok {
			return nil, config.GetErrors().ErrAssertion
		}
		protocol, isAlive := pact.PortScan(p.host, p.port, config.PortScanTimeout)
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

	go func() {
		for host, ports := range ipPortList {
			for _, port := range ports {
				NewPool.Wg.Add(1)
				NewPool.TaskQueue <- NewTask(&Addr{
					host: host,
					port: port,
				}, f)
			}
		}
		close(NewPool.TaskQueue) // 关闭任务队列
		NewPool.Wg.Wait()        // 等待消费者执行完全部任务
		close(NewPool.Result)    // 关闭结果队列
	}()

	result := map[string][]*config.PortProtocol{}
	for res := range NewPool.Result {
		if res == nil {
			continue
		}
		resultSimple := res.(*Addr)
		result[resultSimple.host] = append(result[resultSimple.host], &config.PortProtocol{
			IP:       resultSimple.host,
			Port:     resultSimple.port,
			Protocol: resultSimple.protocol,
		})
	}
	return result, nil
}
