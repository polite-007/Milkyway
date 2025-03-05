package task_raw

import (
	"sync"
)

type Addr struct {
	host     string
	port     int
	protocol string
}

type Task struct {
	args any
	f    func(args any) (any, error)
}

func newTask(args any, f func(args any) (any, error)) *Task {
	return &Task{
		f:    f,
		args: args,
	}
}

type WorkPool struct {
	Result    chan any
	Wg        *sync.WaitGroup
	TaskQueue chan *Task
	WorkerNum int
}

func NewWorkPool(workerNum int) *WorkPool {
	return &WorkPool{
		Result:    make(chan any, workerNum),
		Wg:        &sync.WaitGroup{},
		TaskQueue: make(chan *Task, workerNum),
		WorkerNum: workerNum,
	}
}

func (p *WorkPool) worker() {
	for task := range p.TaskQueue {
		result, err := task.f(task.args)
		if err == nil {
			p.Result <- result
		}
		p.Wg.Done()
	}
}

func (p *WorkPool) Start() {
	for i := 0; i < p.WorkerNum; i++ {
		go p.worker()
	}
}
