package utils

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

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

func SplitHost(host string) (string, int) {
	hosts := strings.Split(host, ":")
	if len(hosts) == 1 {
		return hosts[0], 80
	}
	ip := hosts[0]
	port, _ := strconv.Atoi(hosts[1])
	return ip, port
}

func MapToJson(param map[string][]string) string {
	dataType, _ := json.Marshal(param)
	dataString := string(dataType)
	return dataString
}

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

func IsRegular(str string, keywords []string) bool {
	for _, k := range keywords {
		re := regexp.MustCompile(k)
		if !re.MatchString(str) {
			return false
		}
	}
	return true
}

var (
	urlPattern    = regexp.MustCompile(`^(http|https)://[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(/[^ ]*)?$`)
	domainPattern = regexp.MustCompile(`^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$`)
)

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

// ReadFilesFromDir 读取指定目录下的所有文件
func ReadFilesFromDir(dirPath string) ([][]byte, error) {
	var filesData [][]byte
	info, err := os.Stat(dirPath)
	if err != nil {
		return nil, fmt.Errorf("failed to access directory: %w", err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("path is not a directory: %s", dirPath)
	}
	err = filepath.Walk(dirPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() {
			data, err := ioutil.ReadFile(path)
			if err != nil {
				return fmt.Errorf("failed to read file %s: %w", path, err)
			}
			filesData = append(filesData, data)
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("failed to walk through directory: %w", err)
	}
	return filesData, nil
}
