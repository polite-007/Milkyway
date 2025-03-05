package fileutils

import (
	"archive/zip"
	"bufio"
	"bytes"
	"embed"
	"fmt"
	"io"
	"io/fs"
	"io/ioutil"
	"os"
	"path/filepath"
	"sync"
	"time"
)

var (
	mu = new(sync.Mutex)
)

// FileStruct 文件结构体
type FileStruct struct {
	Name    string
	Content string
}

// ReadLines 读取文件
func ReadLines(filename string) ([]string, error) {
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

	if err = scanner.Err(); err != nil {
		return nil, err
	}

	return lines, nil
}

// ReadByte 读取文件
func ReadByte(filename string) ([]byte, error) {
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
func WriteLines(filename string, lines []string, append bool) error {
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

func WriteString(filename string, content string, append bool) error {
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

// CreateZipStream 创建zip文件流
func CreateZipStream(fileName, Content string) ([]byte, error) {
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

// ReadFileFromZipStream 从zip流读取到zip里的文件名和文件内容
func ReadFileFromZipStream(content []byte) ([]*FileStruct, error) {
	r := bytes.NewReader(content)
	// 打开ZIP文件
	zr, err := zip.NewReader(r, int64(len(content)))
	if err != nil {
		return nil, err
	}
	var files []*FileStruct
	for _, f := range zr.File {
		// 打开文件
		rc, err := f.Open()
		if err != nil {
			return nil, err
		}
		defer rc.Close()

		file := &FileStruct{
			Name: f.Name,
		}
		// 读取文件内容
		data, err := io.ReadAll(rc)
		if err != nil {
			return nil, err
		}
		file.Content = string(data)
		files = append(files, file)
	}
	return files, nil
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

// ReadFilesFromEmbedFs 从嵌入的目录中读取所有文件
func ReadFilesFromEmbedFs(embedFs embed.FS, dir string) ([][]byte, error) {
	var allFilesContent [][]byte
	// 遍历嵌入的目录
	err := fs.WalkDir(embedFs, dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err // 遍历时出错
		}
		if !d.IsDir() { // 如果是文件
			data, err := embedFs.ReadFile(path) // 读取文件内容
			if err != nil {
				return err
			}
			allFilesContent = append(allFilesContent, data) // 添加到结果中
		}
		return nil
	})
	return allFilesContent, err
}

func GenerateEmptyFile(filename string) error {
	flag := os.O_WRONLY | os.O_CREATE | os.O_TRUNC
	file, err := os.OpenFile(filename, flag, 0644)
	if err != nil {
		return err
	}
	defer file.Close()

	// 验证文件是否创建成功
	_, err = os.Stat(filename)
	if err != nil {
		return err
	}
	return nil
}
