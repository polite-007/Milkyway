package utils

import (
	"archive/zip"
	"bufio"
	"bytes"
	"fmt"
	"io"
	"os"
	"sync"
	"time"
)

type fileService struct {
}

var (
	mu   = new(sync.Mutex)
	File = &fileService{}
)

// ReadLines 读取文件
func (f *fileService) ReadLines(filename string) ([]string, error) {
	mu.Lock()
	defer mu.Unlock()

	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	lines := []string{}
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return lines, nil
}

func (f *fileService) Read(filename string) ([]byte, error) {
	mu.Lock()
	defer mu.Unlock()

	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	content, err := io.ReadAll(file)
	if err != nil {
		return nil, err
	}
	return content, nil
}

// WriteLines 写入文件
func (f *fileService) WriteLines(filename string, lines []string, append bool) error {
	mu.Lock()
	defer mu.Unlock()

	var flag int
	if append {
		flag = os.O_WRONLY | os.O_CREATE | os.O_APPEND
	} else {
		flag = os.O_WRONLY | os.O_CREATE | os.O_TRUNC
	}

	file, err := os.OpenFile(filename, flag, 0644)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := bufio.NewWriter(file)
	for _, line := range lines {
		if line == "" {
			continue
		}
		_, err = fmt.Fprintln(file, line)
		if err != nil {
			return err
		}
	}
	return writer.Flush()
}

func (f *fileService) Write(filename string, content string, append bool) error {
	mu.Lock()
	defer mu.Unlock()

	var flag int
	if append {
		flag = os.O_WRONLY | os.O_CREATE | os.O_APPEND
	} else {
		flag = os.O_WRONLY | os.O_CREATE | os.O_TRUNC
	}

	file, err := os.OpenFile(filename, flag, 0644)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := bufio.NewWriter(file)
	_, err = writer.WriteString(content)
	if err != nil {
		return err
	}
	return writer.Flush()
}

// UniqueStrings 去重
func (f *fileService) UniqueStrings(slice []string) []string {
	seen := make(map[string]struct{}) // 使用空结构体来节省内存

	result := []string{}
	for _, value := range slice {
		if _, exists := seen[value]; !exists {
			seen[value] = struct{}{}
			result = append(result, value)
		}
	}
	return result
}

// CreateZipStream 创建zip文件流
func (z *fileService) CreateZipStream(fileName, Content string) ([]byte, error) {
	var buffer bytes.Buffer
	zipWriter := zip.NewWriter(&buffer)
	fileContent := []byte(Content)

	fileHeader := &zip.FileHeader{
		Name:          fileName,    // 文件名
		Method:        zip.Deflate, // 压缩方法
		Modified:      time.Now(),
		ExternalAttrs: 0644,
	}
	writer, err := zipWriter.CreateHeader(fileHeader)
	if err != nil {
		return nil, err
	}
	_, err = writer.Write(fileContent)
	if err != nil {
		return nil, err
	}
	err = zipWriter.Close()
	if err != nil {
		return nil, err
	}
	return buffer.Bytes(), nil
}

type fileStruct struct {
	name    string
	content string
}

// ReadFileFromZipStream 从zip流读取到zip里的文件名和文件内容
func (z *fileService) ReadFileFromZipStream(content []byte) ([]*fileStruct, error) {
	r := bytes.NewReader(content)
	// 打开ZIP文件
	zr, err := zip.NewReader(r, int64(len(content)))
	if err != nil {
		return nil, err
	}
	var files []*fileStruct
	for _, f := range zr.File {
		// 打开文件
		rc, err := f.Open()
		if err != nil {
			return nil, err
		}
		defer rc.Close()

		file := &fileStruct{
			name: f.Name,
		}
		// 读取文件内容
		data, err := io.ReadAll(rc)
		if err != nil {
			return nil, err
		}
		file.content = string(data)
		files = append(files, file)
	}
	return files, nil
}
