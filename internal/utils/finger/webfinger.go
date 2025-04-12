package finger

import (
	"encoding/json"
	"fmt"
	"github.com/polite007/Milkyway/internal/common"
	"strings"
	"sync"

	"github.com/polite007/Milkyway/config"
	"github.com/polite007/Milkyway/pkg/strutils"
	"github.com/polite007/Milkyway/static"
)

type AssetsInfo struct {
	Fingerprint []Fingerprint
}

type Fingerprint struct {
	Cms      string   `json:"cms"`
	Method   string   `json:"method"`
	Location string   `json:"location"`
	Keyword  []string `json:"keyword"`
	Tag      []string `json:"tag"`
}

// 下面的代码是临时进行tags转换用的

var (
	once   sync.Once
	assets AssetsInfo
)

func initFingerFile() {
	fingerFile := "finger/finger_new.json"
	if config.Get().FingerFile != "" {
		fingerFile = config.Get().FingerFile
	}
	content, err := static.EmbedFS.ReadFile(fingerFile)
	if err != nil {
		fmt.Println(err)
		panic(err)
	}
	if err = json.Unmarshal(content, &assets); err != nil {
		panic(err)
	}
}

func WebFinger(resp *common.Resps) (string, []string) {
	once.Do(initFingerFile)
	headers := strutils.MapToJson(resp.Header)
	var cms []string
	var tags []string
	for _, finp := range assets.Fingerprint {
		if finp.Location == "body" {
			if finp.Method == "keyword" {
				if strutils.IsKeyword(resp.Body, finp.Keyword) {
					cms = append(cms, finp.Cms)
					tags = append(tags, finp.Tag...)
				}
			}
			if finp.Method == "faviconhash" {
				if resp.FavHash == finp.Keyword[0] {
					cms = append(cms, finp.Cms)
					tags = append(tags, finp.Tag...)
				}
			}
			if finp.Method == "regular" {
				if strutils.IsRegular(resp.Body, finp.Keyword) {
					cms = append(cms, finp.Cms)
					tags = append(tags, finp.Tag...)
				}
			}
		}
		if finp.Location == "header" {
			if finp.Method == "keyword" {
				if strutils.IsKeyword(headers, finp.Keyword) {
					cms = append(cms, finp.Cms)
					tags = append(tags, finp.Tag...)
				}
			}
			if finp.Method == "regular" {
				if strutils.IsRegular(headers, finp.Keyword) {
					cms = append(cms, finp.Cms)
					tags = append(tags, finp.Tag...)
				}
			}
		}
		if finp.Location == "title" {
			if finp.Method == "keyword" {
				if strutils.IsKeyword(resp.Title, finp.Keyword) {
					cms = append(cms, finp.Cms)
					tags = append(tags, finp.Tag...)
				}
			}
			if finp.Method == "regular" {
				if strutils.IsRegular(resp.Title, finp.Keyword) {
					cms = append(cms, finp.Cms)
					tags = append(tags, finp.Tag...)
				}
			}
		}
	}
	if len(cms) == 0 {
		return "", nil
	}
	cms = strutils.RemoveDuplicateSliceString(cms)
	tags = strutils.RemoveDuplicateSliceString(tags)
	return strings.Join(cms, "|"), tags
}
