package color

import (
	"github.com/fatih/color"
	"regexp"
)

var (
	ansiRegex = regexp.MustCompile(`\x1b\[[0-9;]*m`)
	Green     = color.New(color.FgGreen).SprintFunc()
	Red       = color.New(color.FgRed).SprintFunc()
	Yellow    = color.New(color.FgYellow).SprintFunc()
)

func RemoveColor(input string) string {
	// 正则表达式匹配 ANSI 转义序列
	return ansiRegex.ReplaceAllString(input, "")
}
