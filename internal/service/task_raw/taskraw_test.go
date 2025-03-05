package task_raw

import (
	"github.com/polite007/Milkyway/config"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestTask(t *testing.T) {
	// 初始化线程池, 并启动
	NewPool := NewWorkPool(10)
	NewPool.Start()

	f := func(args any) (any, error) {
		arg, ok := args.(int)
		if !ok {
			return nil, config.GetErrors().ErrAssertion
		}
		return arg, nil
	}

	go func() { // 模拟生产者，获取到全部任务后，额外开一个协程进行任务提交
		for i := 1; i <= 10000; i++ {
			NewPool.Wg.Add(1)                  //
			NewPool.TaskQueue <- newTask(i, f) // 将任务放入任务队列
		}
		close(NewPool.TaskQueue) // 关闭任务队列
		NewPool.Wg.Wait()        // 等待消费者执行完全部任务
		close(NewPool.Result)    // 关闭结果队列
	}()

	var result int
	for resultRaw := range NewPool.Result { // 读取结果
		result += resultRaw.(int)
	}
	assert.Equal(t, 50005000, result)
}
