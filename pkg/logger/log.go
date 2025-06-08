package logger

import (
	"fmt"
	"io"
	"log"
	"math/rand"
	"os"
	"path/filepath"
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
	LogName      string // default log.txt

	// internal variables
	logChan = make(chan *string, 1500)
)

// 生成6位随机数
func generateSixDigitNumber() int {
	rand.Seed(time.Now().UnixNano())
	return rand.Intn(900000) + 100000
}

func init() {
	// 创建 logs 目录
	logsDir := "logs"
	if err := os.MkdirAll(logsDir, 0755); err != nil {
		fmt.Printf("创建日志目录失败: %v\n", err)
		return
	}

	// 设置日志文件名
	LogName = filepath.Join(logsDir, fmt.Sprintf("log_%d.txt", generateSixDigitNumber()))

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
		logChan <- &result
	}
}

func OutLogSuccess(result string) {
	if result != "" {
		result = fmt.Sprintf("[%s] %s", color.Green("OK"), color.Green(result))
		LogWaitGroup.Add(1)
		logChan <- &result
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
