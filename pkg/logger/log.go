package logger

import (
	"fmt"
	"io"
	"log"
	"sync"

	"github.com/polite007/Milkyway/pkg/color"
	"github.com/polite007/Milkyway/pkg/fileutils"
)

// 用法
// 1：调用 OutLog(result)
// 2：日志导入完毕，调用 LogWaitGroup.Wait()

var (
	// external variables
	LogWaitGroup sync.WaitGroup
	LogName      = "log.txt" // default log.txt

	// internal variables
	logChan = make(chan *string, 1500)
)

func init() {
	log.SetOutput(io.Discard)
	go saveLog(LogName)
}

func OutLog(result string) {
	if result != "" {
		fmt.Printf(result)
		LogWaitGroup.Add(1)
		logChan <- &result
	}
}

func saveLog(logName string) {
	for logout := range logChan {
		logOutStr := *logout
		_ = fileutils.WriteString(logName, color.RemoveColor(logOutStr), true)
		LogWaitGroup.Done()
	}
}
