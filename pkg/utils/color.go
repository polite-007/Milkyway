package utils

import (
	"github.com/fatih/color"
	"regexp"
)

var (
	Green  = color.New(color.FgGreen).SprintFunc()
	Red    = color.New(color.FgRed).SprintFunc()
	Yellow = color.New(color.FgYellow).SprintFunc()
	Blue   = color.New(color.FgBlue).SprintFunc()
)

func RemoveColor(input string) string {
	// 正则表达式匹配 ANSI 转义序列
	re := regexp.MustCompile(`\x1b\[[0-9;]*m`)
	return re.ReplaceAllString(input, "")
}
