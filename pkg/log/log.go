package log

import (
	"fmt"
	_const "github.com/polite007/Milkyway/common/const"
	"github.com/polite007/Milkyway/pkg/utils"
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
	go SaveLog()
}

func OutLog(result string) {
	if result != "" {
		fmt.Printf(result)
		LogWaitGroup.Add(1)
		logChan <- &result
	}
}

func SaveLog() {
	for logout := range logChan {
		logOutStr := *logout
		_ = utils.File.Write(_const.OutputFileName, utils.RemoveColor(logOutStr), true)
		LogWaitGroup.Done()
	}
}
