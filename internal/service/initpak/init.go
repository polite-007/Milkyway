package initpak

import (
	"encoding/json"
	"fmt"
	"github.com/polite007/Milkyway/config"
	proxy2 "github.com/polite007/Milkyway/internal/service/connx"
	"github.com/polite007/Milkyway/internal/utils"
	"github.com/polite007/Milkyway/pkg/neutron/protocols"
	http2 "github.com/polite007/Milkyway/pkg/neutron/protocols/http"
	"github.com/polite007/Milkyway/pkg/neutron/templates"
	"github.com/polite007/Milkyway/static"
	"golang.org/x/net/proxy"
	"gopkg.in/yaml.v3"
	"io/fs"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

var (
	PocsList        []*templates.Template
	ExecuterOptions *protocols.ExecuterOptions
)

var (
	Assets AssetsInfo
	Once   sync.Once
)

type AssetsInfo struct {
	Fingerprint []Fingerprint
}

type Fingerprint struct {
	Cms      string
	Method   string
	Location string
	Keyword  []string
	Tag      []string
}

func ReadAllFilesContent() ([][]byte, error) {
	var allFilesContent [][]byte
	// 遍历嵌入的目录
	err := fs.WalkDir(static.EmbedFS, "poc", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err // 遍历时出错
		}
		if !d.IsDir() { // 如果是文件
			data, err := static.EmbedFS.ReadFile(path) // 读取文件内容
			if err != nil {
				return err
			}
			allFilesContent = append(allFilesContent, data) // 添加到结果中
		}
		return nil
	})
	return allFilesContent, err
}

func InitFingerFile() {
	fingerFile := "finger/finger.json"
	if config.Get().FingerFile != "" {
		fingerFile = config.Get().FingerFile
	}
	content, err := static.EmbedFS.ReadFile(fingerFile)
	if err != nil {
		fmt.Println(err)
		panic(err)
	}
	if err = json.Unmarshal(content, &Assets); err != nil {
		panic(err)
	}
}

func InitNucleiPocList() error {
	var (
		pocFile [][]byte
		err     error
	)
	if config.Get().PocFile != "" {
		pocFile, err = utils.ReadFilesFromDir(config.Get().PocFile)
		if err != nil {
			return err
		}
	} else {
		pocFile, err = ReadAllFilesContent()
		if err != nil {
			return err
		}
	}

	defer func() {
		fmt.Printf("[*] 当前poc库漏洞数: %d\n", len(PocsList))
	}()

	if config.Get().PocId != "" {
		for _, poc := range pocFile {
			t := &templates.Template{}
			err = yaml.Unmarshal(poc, t)
			if err != nil {
				continue
			}
			err = t.Compile(ExecuterOptions)
			if err != nil {
				continue
			}
			if config.Get().PocId == t.Id {
				PocsList = append(PocsList, t)
				return nil
			}
		}
	}

	if config.Get().PocTags != "" {
		pocTags := strings.Split(config.Get().PocTags, ",")
		for _, poc := range pocFile {
			t := &templates.Template{}
			err = yaml.Unmarshal(poc, t)
			if err != nil {
				continue
			}
			err = t.Compile(ExecuterOptions)
			if err != nil {
				continue
			}

			if utils.HasCommonElement(pocTags, t.GetTags()) {
				PocsList = append(PocsList, t)
			}
		}
		return nil
	}
	for _, poc := range pocFile {
		t := &templates.Template{}
		err = yaml.Unmarshal(poc, t)
		if err != nil {
			continue
		}
		err = t.Compile(ExecuterOptions)
		if err != nil {
			continue
		}
		PocsList = append(PocsList, t)
	}
	return nil
}

func InitNculeiProxy() {
	if config.Get().HttpProxy != "" {
		Url, err := url.Parse(config.Get().HttpProxy)
		if err != nil {
			return
		}
		http2.DefaultTransport.Proxy = http.ProxyURL(Url)
		fmt.Println("1")
		return
	}

	if config.Get().Socks5Proxy != "" {
		Dail := &net.Dialer{
			Timeout:   5 * time.Second,
			KeepAlive: 5 * time.Second,
		}
		socks5Proxy, err := proxy2.Socks5Dailer(Dail)
		if err != nil {
			return
		}
		if contextDialer, ok := socks5Proxy.(proxy.ContextDialer); ok {
			http2.DefaultTransport.DialContext = contextDialer.DialContext
			//Client.Transport = defaultTransport
			return
		} else {
			return
		}
	}
}
