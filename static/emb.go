package static

import (
	"embed"
	"encoding/json"
	"fmt"
	_const "github.com/polite007/Milkyway/common/const"
	"sync"
)

//go:embed finger/finger.json poc
var EmbedFS embed.FS

var (
	Assets AssetsInfo
	Once   sync.Once
)

type AssetsInfo struct {
	Fingerprint []Fingerprint
}

type Fingerprint struct {
	Cms      string
	Method   string
	Location string
	Keyword  []string
	Tag      []string
}

func InitFingerFile() {
	fingerFile := "finger/finger.json"
	if _const.FingerFile != "" {
		fingerFile = _const.FingerFile
	}
	content, err := EmbedFS.ReadFile(fingerFile)
	if err != nil {
		fmt.Println(err)
		panic(err)
	}
	if err = json.Unmarshal(content, &Assets); err != nil {
		panic(err)
	}
}
