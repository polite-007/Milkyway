package logger

import (
	"fmt"
	"github.com/polite007/Milkyway/config"
	"github.com/polite007/Milkyway/internal/utils"
	"github.com/polite007/Milkyway/internal/utils/color"
	"io"
	"log"
	"sync"
)

var (
	LogWaitGroup sync.WaitGroup
	logChan      = make(chan *string, 1500)
)

func init() {
	log.SetOutput(io.Discard)
	go saveLog()
}

func OutLog(result string) {
	if result != "" {
		fmt.Printf(result)
		LogWaitGroup.Add(1)
		logChan <- &result
	}
}

func saveLog() {
	for logout := range logChan {
		logOutStr := *logout
		_ = utils.File.Write(config.Get().OutputFileName, color.RemoveColor(logOutStr), true)
		LogWaitGroup.Done()
	}
}
