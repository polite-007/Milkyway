package module

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"strings"
)

func localFile(filename string) (urls []string) {
	file, err := os.Open(filename)
	if err != nil {
		log.Println("Local file read error:", err)
		fmt.Println("[error] the input file is wrong!!!")
		os.Exit(1)
	}
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		if strings.Contains(scanner.Text(), "http") {
			urls = append(urls, scanner.Text())
		} else {
			urls = append(urls, "https://"+scanner.Text())
		}
	}
	return removeRepeatedElement(urls)
}

func removeRepeatedElement(urls []string) (newUrls []string) {
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
