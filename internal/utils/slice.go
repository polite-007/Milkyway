package utils

import (
	"encoding/json"
	"regexp"
	"strconv"
	"strings"
)

var (
	urlPattern    = regexp.MustCompile(`^(http|https)://[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(/[^ ]*)?$`)
	domainPattern = regexp.MustCompile(`^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$`)
)

// UniqueAppend 追加不重复元素到切片中
func UniqueAppend(slice []string, element ...string) []string {
	exists := make(map[string]bool)
	for _, v := range slice {
		exists[v] = true
	}
	for _, v := range element {
		if !exists[v] {
			slice = append(slice, v)
			exists[v] = true
		}
	}
	return slice
}

// RemoveDuplicateSliceInt 移除int切片中的重复元素
func RemoveDuplicateSliceInt(old []int) []int {
	temp := make(map[int]struct{}, len(old))
	result := make([]int, 0, len(old))
	for _, item := range old {
		if _, exists := temp[item]; !exists {
			temp[item] = struct{}{}
			result = append(result, item)
		}
	}
	return result
}

// RemoveDuplicateSliceString 移除string切片中的重复元素
func RemoveDuplicateSliceString(slice []string) []string {
	temp := make(map[string]struct{}, len(slice))
	result := make([]string, 0, len(slice))
	for _, item := range slice {
		if _, exists := temp[item]; !exists {
			temp[item] = struct{}{}
			result = append(result, item)
		}
	}
	return result
}

// SplitHost 分割host, host-> ip, port
func SplitHost(host string) (string, int) {
	hosts := strings.Split(host, ":")
	if len(hosts) == 1 {
		return hosts[0], 80
	}
	ip := hosts[0]
	port, _ := strconv.Atoi(hosts[1])
	return ip, port
}

// MapToJson map转json
func MapToJson(param map[string][]string) string {
	dataType, _ := json.Marshal(param)
	dataString := string(dataType)
	return dataString
}

// IsKeyword 判断是否包含关键字
func IsKeyword(str string, keywords []string) bool {
	if str == "" || len(keywords) == 0 {
		return false
	}
	for _, k := range keywords {
		if !strings.Contains(str, k) {
			return false
		}
	}
	return true
}

// IsRegular 判断是否包含正则
func IsRegular(str string, keywords []string) bool {
	for _, k := range keywords {
		re := regexp.MustCompile(k)
		if !re.MatchString(str) {
			return false
		}
	}
	return true
}

// IsDomain 判断是否为域名
func IsDomain(str string) ([]string, bool) {
	if strings.Contains(str, "http://") || strings.Contains(str, "https://") {
		return []string{str}, true
	}

	if urlPattern.MatchString(str) {
		return []string{str}, true
	}

	if domainPattern.MatchString(str) {
		return []string{"http://" + str, "https://" + str}, true
	}

	return nil, false
}

// HasCommonElement 检查两个字符串切片是否有共同元素
func HasCommonElement(slice1 []string, slice2 []string) bool {
	elementMap := make(map[string]bool)
	for _, item := range slice1 {
		elementMap[item] = true
	}
	for _, item := range slice2 {
		if elementMap[item] {
			return true
		}
	}
	return false
}
