package initpak

import (
	"fmt"
	"strings"
	"testing"

	"github.com/polite007/Milkyway/pkg/fileutils"
	"github.com/polite007/Milkyway/pkg/strutils"
)

func Test_GetPocAllTag(t *testing.T) {
	if err := initNucleiPocList("poc_all"); err != nil {
		panic(err)
	}
	fmt.Printf("当前poc数量：%d\n", len(PocsList))
	var tags []string
	for _, poc := range PocsList {
		var simpleTags []string
		for _, tag := range poc.GetTags() {
			// 过滤掉cve,cnvd,cnnvd
			if strings.Contains(tag, "cve") {
				continue
			}
			if strings.Contains(tag, "cnvd") {
				continue
			}
			if strings.Contains(tag, "cnnvd") {
				continue
			}
			simpleTags = append(simpleTags, tag)
		}
		tags = strutils.UniqueAppend(tags, simpleTags...)
	}
	fmt.Printf("当前poc标签数量：%d\n", len(tags))
	if err := fileutils.WriteLines("tags.txt", tags, false); err != nil {
		panic(err)
	}
}
