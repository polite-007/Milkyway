package finger

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/polite007/Milkyway/pkg/fileutils"
	"github.com/polite007/Milkyway/pkg/strutils"
	"strings"
	"sync"
	"testing"
)

type CnEN struct {
	CN string
	EN string
}

var cnEns = []CnEN{
	{CN: "致远", EN: "seeyon"},
	{CN: "金蝶", EN: "kingdee"},
	{CN: "金和", EN: "jinher"},
	{CN: "泛微", EN: "fanwei"},
	{CN: "致远互联", EN: "seeyon"},
	{CN: "华天", EN: "huatian"},
	{CN: "华天动力", EN: "huatian"},
	{CN: "用友", EN: "yonyou"},
	{CN: "红帆", EN: "ioffice"},
	{CN: "帆软报表", EN: "fanruan"},
	{CN: "致远互联", EN: "seeyon"},
}

func enCnToEN(s string) string {
	for _, cnEn := range cnEns {
		if strings.Contains(s, cnEn.CN) {
			return cnEn.EN
		}
	}
	return s
}

func structToString(s AssetsInfo) string { // 创建一个缓冲区
	var buffer bytes.Buffer
	encoder := json.NewEncoder(&buffer)
	// 禁用HTML转义
	encoder.SetEscapeHTML(false)
	// 设置缩进
	encoder.SetIndent("", "  ")
	// 编码数据
	err := encoder.Encode(s)
	if err != nil {
		panic(err)
	}
	return buffer.String()
}

func Test_GetFinger(t *testing.T) {
	initFingerFile()
	fmt.Printf("指纹数量：%d\n", len(assets.Fingerprint))
	// 新的finger
	var assetsNew AssetsInfo
	// 获取所有nuclei的poc标签
	pocTagContent, err := fileutils.ReadLines("tags.txt")
	if err != nil {
		panic(err)
	}
	fmt.Printf("当前poc标签数量：%d\n", len(pocTagContent))
	// 遍历poc标签存入map中
	var pocTag sync.Map
	for _, tag := range pocTagContent {
		pocTag.Store(tag, "")
	}
	// 遍历旧的finger,构造新的finger
	for _, finger := range assets.Fingerprint {
		assetsSimple := Fingerprint{
			Cms:      finger.Cms,
			Keyword:  finger.Keyword,
			Location: finger.Location,
			Method:   finger.Method,
			Tag:      []string{"unknown"},
		}
		// 按空格进行分割
		for _, cms := range strings.Split(finger.Cms, " ") {
			cms = enCnToEN(cms)
			df := strings.ToLower(cms)
			if _, ok := pocTag.Load(df); ok {
				assetsSimple.Tag = strutils.UniqueAppend(assetsSimple.Tag, df)
			}
		}
		// 按中文/英文分割
		for _, cms := range strutils.SplitChineseAndEnglish(finger.Cms) {
			cms = enCnToEN(cms)
			df := strings.ToLower(cms)
			if _, ok := pocTag.Load(df); ok {
				assetsSimple.Tag = strutils.UniqueAppend(assetsSimple.Tag, df)
			}
		}
		// 按-分割
		for _, cms := range strings.Split(finger.Cms, "-") {
			cms = enCnToEN(cms)
			df := strings.ToLower(cms)
			if _, ok := pocTag.Load(df); ok {
				assetsSimple.Tag = strutils.UniqueAppend(assetsSimple.Tag, df)
			}
		}
		assetsNew.Fingerprint = append(assetsNew.Fingerprint, assetsSimple)
	}
	// 写入json文件
	content := structToString(assetsNew)
	err = fileutils.WriteString("finger_new.json", string(content), false)
	if err != nil {
		panic(err)
	}
}
