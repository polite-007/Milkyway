package strutils

import (
	"fmt"
)

// BytesToInt 将字节数组转换为十进制整数
func BytesToInt(bytes []byte) int {
	var result uint64
	for _, byteVal := range bytes {
		result = (result << 8) | uint64(byteVal)
	}
	return int(result)
}

// IsPrintableInfo 判断是否为可打印字符
func IsPrintableInfo(bytes []byte) string {
	str := ""
	for _, b := range bytes {
		if b >= 32 && b <= 126 {
			str += fmt.Sprintf("%c", b)
		} else {
			str += fmt.Sprintf("\\x%02X", b)
		}
	}
	return str
}
