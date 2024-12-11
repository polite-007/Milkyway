package static

import (
	"fmt"
	"github.com/polite007/Milkyway/pkg/utils"
	"regexp"
	"strings"
	"testing"
)

// 检查并替换tag字段值为数组格式
func replaceTagWithArray(input string) string {
	// 使用正则表达式匹配 "tag": "value" 或 "tag": "value1,value2" 格式
	re := regexp.MustCompile(`"tag":\s*"([^"]+)"`)

	// 替换函数，将逗号分隔的字符串转为数组
	output := re.ReplaceAllStringFunc(input, func(match string) string {
		// 提取tag字段中的值（去掉前后的引号）
		contents := match[8 : len(match)-1] // match 是整个 "tag": "erp,upload"
		// 分割字符串
		values := strings.Split(contents, ",")
		// 将值列表转化为数组格式字符串
		arrayStr := "[\"" + strings.Join(values, ",") + "\"]"
		return `"tag": ` + arrayStr
	})

	return output
}

func TestI(t *testing.T) {
	oldfile := "finger/finger.json"
	newfile := "new.json"

	resultOld, err := utils.File.ReadLines(oldfile)
	if err != nil {
		fmt.Println("读取文件失败:", err)
		return
	}
	fmt.Println(len(resultOld))
	var resultNew []string
	for _, line := range resultOld {
		line = replaceTagWithArray(line)
		resultNew = append(resultNew, line)
	}
	err = utils.File.WriteLines(newfile, resultNew, false)
	if err != nil {
		fmt.Println("写入文件失败:", err)
		return
	}
}
