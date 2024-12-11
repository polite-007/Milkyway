package task

import (
	"fmt"
	_const "github.com/polite007/Milkyway/common/const"
	"github.com/polite007/Milkyway/common/http_custom"
	"github.com/polite007/Milkyway/common/port_scan"
	"github.com/polite007/Milkyway/common/protocol_scan"
	"github.com/polite007/Milkyway/common/vulprotocol"
	"github.com/polite007/Milkyway/common/webfinger"
	"github.com/polite007/Milkyway/pkg/log"
	"github.com/polite007/Milkyway/pkg/neutron/templates"
	"github.com/polite007/Milkyway/pkg/utils"
	"math/rand"
	"time"
)

type Addr struct {
	host     string
	port     int
	protocol string
}

type PocTask struct {
	Poc       *templates.Template
	TargetUrl string
}

func NewIPScanTask(ipList []string) ([]string, error) {
	// 自定义消费者的内部函数
	NewPool := NewWorkPool(_const.WorkPoolNum)
	NewPool.Start()

	f := func(args any) (any, error) {
		ip, ok := args.(string)
		if !ok {
			return nil, _const.ErrAssertion
		}
		isAlive := protocol_scan.ICMPCheck(ip, _const.ICMPTimeOut)
		if !isAlive {
			return "", nil
		} else {
			return ip, nil
		}
	}

	go func() {
		for _, ip := range ipList {
			NewPool.Wg.Add(1)
			NewPool.TaskQueue <- NewTask(ip, f)
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

func NewPortScanTask1(ipPortList map[string][]int) (map[string][]*_const.PortProtocol, error) {
	NewPool := NewWorkPool(_const.WorkPoolNum)
	NewPool.Start()

	f := func(args any) (any, error) {
		p, ok := args.(*Addr)
		if !ok {
			return nil, _const.ErrAssertion
		}
		protocol, isAlive := port_scan.PortScan(p.host, p.port, _const.PortScanTimeout)
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

	result := map[string][]*_const.PortProtocol{}
	for res := range NewPool.Result {
		if res == nil {
			continue
		}
		resultSimple := res.(*Addr)
		result[resultSimple.host] = append(result[resultSimple.host], &_const.PortProtocol{
			IP:       resultSimple.host,
			Port:     resultSimple.port,
			Protocol: resultSimple.protocol,
		})
	}
	return result, nil
}

func NewPortScanTask(ipPortList map[string][]int) (map[string][]*_const.PortProtocol, error) {
	var PortScanTask []*Addr
	NewPool := NewWorkPool(_const.WorkPoolNum)
	NewPool.Start()

	f := func(args any) (any, error) {
		p, ok := args.(*Addr)
		if !ok {
			return nil, _const.ErrAssertion
		}
		protocol, isAlive := port_scan.PortScan(p.host, p.port, _const.PortScanTimeout)
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

	result := map[string][]*_const.PortProtocol{}
	for res := range NewPool.Result {
		if res == nil {
			continue
		}
		resultSimple := res.(*Addr)
		result[resultSimple.host] = append(result[resultSimple.host], &_const.PortProtocol{
			IP:       resultSimple.host,
			Port:     resultSimple.port,
			Protocol: resultSimple.protocol,
		})
	}
	return result, nil
}

func NewWebScanTask(ipPortList map[string][]*_const.PortProtocol) (map[string][]*_const.PortProtocol, []*http_custom.Resps, error) {
	NewPool := NewWorkPool(_const.WorkPoolNum)
	NewPool.Start()

	f := func(args any) (any, error) {
		p, ok := args.(*Addr)
		if !ok {
			return nil, _const.ErrAssertion
		}
		isAlive, err := http_custom.Get(fmt.Sprintf("http://%s:%d", p.host, p.port), nil, "/")
		if err == nil && isAlive.StatusCode != 400 {
			return http_custom.HandleResponse(isAlive)
		}

		isAlive, err = http_custom.Get(fmt.Sprintf("https://%s:%d", p.host, p.port), nil, "/")
		if err == nil && isAlive.StatusCode != 400 {
			return http_custom.HandleResponse(isAlive)
		}

		return nil, _const.ErrTaskFailed
	}

	ipPortListNew := map[string][]*_const.PortProtocol{}
	var result []*http_custom.Resps

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
		resultSimple := res.(*http_custom.Resps)
		ip, port := utils.SplitHost(resultSimple.Url.Host)
		ipPortListNew[ip] = append(ipPortListNew[ip], &_const.PortProtocol{
			IP:       ip,
			Port:     port,
			Protocol: "http",
		})
		resultSimple.Cms, resultSimple.Tags = webfinger.WebFinger(resultSimple)
		var logOut string
		if resultSimple.Cms == "" {
			logOut = fmt.Sprintf("[%s] %-25v len:%d title:%s header: %s\n",
				utils.Green(resultSimple.StatusCode),
				resultSimple.Url,
				len(resultSimple.Body),
				utils.Green(resultSimple.Title),
				utils.Green(resultSimple.Server),
			)
		} else {
			logOut = fmt.Sprintf("[%s] %-25v len:%d title:%s header: %s cms: %s\n",
				utils.Green(resultSimple.StatusCode),
				resultSimple.Url,
				len(resultSimple.Body),
				utils.Green(resultSimple.Title),
				utils.Green(resultSimple.Server),
				utils.Red(resultSimple.Cms),
			)
		}
		log.OutLog(logOut)
		result = append(result, resultSimple)
	}

	return ipPortListNew, result, nil
}

func NewWebScanWithDomainTask(targetUrls []string) ([]*http_custom.Resps, error) {
	NewPool := NewWorkPool(_const.WorkPoolNum)
	NewPool.Start()

	f := func(args any) (any, error) {
		p, ok := args.(string)
		if !ok {
			return nil, _const.ErrAssertion
		}
		if p[len(p)-1] == '/' {
			p = p[:len(p)-2]
		}
		isAlive, err := http_custom.Get(p, nil, "/")
		if err == nil && isAlive.StatusCode != 400 {
			return http_custom.HandleResponse(isAlive)
		}

		isAlive, err = http_custom.Get(p, nil, "/")
		if err == nil && isAlive.StatusCode != 400 {
			return http_custom.HandleResponse(isAlive)
		}

		return nil, _const.ErrTaskFailed
	}

	go func() {
		for _, targetUrl := range targetUrls {
			NewPool.Wg.Add(1)
			NewPool.TaskQueue <- NewTask(targetUrl, f)
		}
		close(NewPool.TaskQueue) // 关闭任务队列
		NewPool.Wg.Wait()        // 等待消费者执行完全部任务
		close(NewPool.Result)    // 关闭结果队列
	}()

	var result []*http_custom.Resps
	for res := range NewPool.Result {
		if res == nil {
			continue
		}
		resultSimple := res.(*http_custom.Resps)
		var logOut string
		resultSimple.Cms, resultSimple.Tags = webfinger.WebFinger(resultSimple)
		if resultSimple.Cms == "" {
			logOut = fmt.Sprintf("[%s] %-25v len:%d title:%s header: %s",
				utils.Green(resultSimple.StatusCode),
				resultSimple.Url,
				len(resultSimple.Body),
				utils.Green(resultSimple.Title),
				utils.Green(resultSimple.Server),
			)
		} else {
			logOut = fmt.Sprintf("[%s] %-25v len:%d title:%s header: %s cms: %s\n",
				utils.Green(resultSimple.StatusCode),
				resultSimple.Url,
				len(resultSimple.Body),
				utils.Green(resultSimple.Title),
				utils.Green(resultSimple.Server),
				utils.Red(resultSimple.Cms),
			)
		}
		log.OutLog(logOut)
		result = append(result, resultSimple)
	}
	return result, nil
}

func NewProtocolVulScan(ipPortList map[string][]*_const.PortProtocol) error {
	NewPool := NewWorkPool(_const.WorkPoolNum)
	NewPool.Start()

	f := func(args any) (any, error) {
		p, ok := args.(*_const.PortProtocol)
		if !ok {
			return nil, _const.ErrAssertion
		}
		vulprotocol.ProtocolVulScan(p.IP, p.Port, p.Protocol)
		return nil, _const.ErrTaskFailed
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
	for _ = range NewPool.Result {
	}
	return nil
}

func NewWebPocVulScan(pocTask []*PocTask) error {
	NewPool := NewWorkPool(_const.WorkPoolNum)
	NewPool.Start()

	f := func(args any) (any, error) {
		p, ok := args.(*PocTask)
		if !ok {
			return nil, _const.ErrAssertion
		}
		res, _ := p.Poc.Execute(p.TargetUrl, nil)
		if res != nil {
			if res.Matched || res.Extracted {
				result := fmt.Sprintf("[*] %s %s id: %s\n", p.TargetUrl, utils.Red(p.Poc.Info.Name), p.Poc.Id)
				log.OutLog(result)
			}
		}
		return nil, _const.ErrTaskFailed
	}

	go func() {
		for _, poc := range pocTask {
			NewPool.Wg.Add(1)
			NewPool.TaskQueue <- NewTask(poc, f)
		}
		close(NewPool.TaskQueue) // 关闭任务队列
		NewPool.Wg.Wait()        // 等待消费者执行完全部任务
		close(NewPool.Result)    // 关闭结果队列
	}()
	for _ = range NewPool.Result {
	}
	return nil
}
