package filehandle

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

func ReadUrlsFromFile(filename string) (urls []string, err error) {
	urls, err = ReadLinesFromFile(filename)
	if err != nil {
		return nil, err
	}
	for _, url := range urls {
		if strings.Contains(url, "http") {
			urls = append(urls, url)
		} else {
			urls = append(urls, "http://"+url)
			urls = append(urls, "https://"+url)
		}
	}
	return RemoveRepeatedElement(urls), nil
}

func RemoveRepeatedElement(urls []string) (newUrls []string) {
	newUrls = make([]string, 0)
	for i := 0; i < len(urls); i++ {
		repeat := false
		for j := i + 1; j < len(urls); j++ {
			if urls[i] == urls[j] {
				repeat = true
				break
			}
		}
		if !repeat {
			newUrls = append(newUrls, urls[i])
		}
	}
	return newUrls
}

func WriteLinesToFile(filename string, lines []string) error {
	file, err := os.OpenFile(filename, os.O_WRONLY|os.O_CREATE, 0644)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := bufio.NewWriter(file)
	for _, line := range lines {
		if line == "" {
			continue
		}
		fmt.Fprintln(writer, line)
	}
	return writer.Flush()
}

func ReadLinesFromFile(filename string) ([]string, error) {
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
