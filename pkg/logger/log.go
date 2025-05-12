package logger

import (
	"fmt"
	"io"
	"log"
	"math/rand"
	"strings"
	"sync"
	"time"

	"github.com/polite007/Milkyway/pkg/color"
	"github.com/polite007/Milkyway/pkg/fileutils"
)

// 用法
// 1：调用 OutLog(result)
// 2：日志导入完毕，调用 LogWaitGroup.Wait()

var (
	// external variables
	LogWaitGroup sync.WaitGroup
	LogName      = fmt.Sprintf("log_%d.txt", generateSixDigitNumber()) // default log.txt

	// internal variables
	logChan = make(chan *string, 1500)
)

// 生成6位随机数
func generateSixDigitNumber() int {
	rand.Seed(time.Now().UnixNano())
	return rand.Intn(900000) + 100000
}

func init() {
	log.SetOutput(io.Discard)
	go saveLog(LogName)
}

func OutLog(result string) {
	if result != "" {
		LogWaitGroup.Add(1)
		logChan <- &result
	}
}

func OutLogInfo(result string) {
	if result != "" {
		result = fmt.Sprintf("[%s] %s", color.Yellow("INFO"), color.Green(result))
		LogWaitGroup.Add(1)
		logChan <- &result
	}
}

func OutLogError(result string) {
	if result != "" {
		result = fmt.Sprintf("[%s] %s", color.Red("ERROR"), color.Green(result))
		LogWaitGroup.Add(1)
	}
}

func OutLogSuccess(result string) {
	if result != "" {
		result = fmt.Sprintf("[%s] %s", color.Green("OK"), color.Green(result))
		LogWaitGroup.Add(1)
	}
}

func saveLog(logName string) {
	for logout := range logChan {
		logOutStr := *logout
		if strings.Contains(logOutStr, "\n") {
			fmt.Printf(logOutStr)
		} else {
			fmt.Println(logOutStr)
			logOutStr += "\n"
		}
		_ = fileutils.WriteString(logName, color.RemoveColor(logOutStr), true)
		LogWaitGroup.Done()
	}
}
