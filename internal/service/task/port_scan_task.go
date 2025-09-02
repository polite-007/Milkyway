package task

import (
	"math/rand"
	"time"

	"github.com/polite007/Milkyway/config"
	"github.com/polite007/Milkyway/internal/service/protocol/protocol_scan"
)

// newPortScanTask 返回存活的端口和对应的协议
func newPortScanTask(ipPortList []*config.IpPorts) (*config.TargetList, error) {
	var PortScanTask []*Addr
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
	var size int
	for _, ipPort := range ipPortList {
		size += len(ipPort.Ports)
		for _, port := range ipPort.Ports {
			PortScanTask = append(PortScanTask, &Addr{
				host: ipPort.IP,
				port: port,
			})
		}
	}
	//proGress := progress.GetNewProgress(size)

	rand.Seed(time.Now().UnixNano())
	rand.Shuffle(len(PortScanTask), func(i, j int) {
		PortScanTask[i], PortScanTask[j] = PortScanTask[j], PortScanTask[i]
	})
	go func() {
		for _, p := range PortScanTask {
			NewPool.Wg.Add(1)
			NewPool.TaskQueue <- newTask(p, f)
		}
		close(NewPool.TaskQueue) // 关闭任务队列
		NewPool.Wg.Wait()        // 等待消费者执行完全部任务
		close(NewPool.Result)    // 关闭结果队列
	}()

	result := config.NewIpPortProtocolList()
	for res := range NewPool.Result {
		//proGress.Add(1)
		if res == nil {
			continue
		}
		resultSimple := res.(*Addr)
		result.Add(resultSimple.host, resultSimple.port, resultSimple.protocol)
	}
	return result, nil
}

func newPortScanTaskRandom(ipPortList []*config.IpPorts) (*config.TargetList, error) {
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

	go func() {
		for _, ipPort := range ipPortList {
			for _, port := range ipPort.Ports {
				NewPool.Wg.Add(1)
				NewPool.TaskQueue <- newTask(&Addr{
					host: ipPort.IP,
					port: port,
				}, f)
			}
		}
		close(NewPool.TaskQueue) // 关闭任务队列
		NewPool.Wg.Wait()        // 等待消费者执行完全部任务
		close(NewPool.Result)    // 关闭结果队列
	}()

	result := config.NewIpPortProtocolList()
	for res := range NewPool.Result {
		if res == nil {
			continue
		}
		resultSimple := res.(*Addr)
		result.Add(resultSimple.host, resultSimple.port, resultSimple.protocol)
	}
	return result, nil
}
