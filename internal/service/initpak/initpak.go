package initpak

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/polite007/Milkyway/config"
	"github.com/polite007/Milkyway/internal/utils/httpx"
	proxy2 "github.com/polite007/Milkyway/internal/utils/proxy"
	"github.com/polite007/Milkyway/pkg/fileutils"
	"github.com/polite007/Milkyway/pkg/neutron/protocols"
	http2 "github.com/polite007/Milkyway/pkg/neutron/protocols/http"
	"github.com/polite007/Milkyway/pkg/neutron/templates"
	"github.com/polite007/Milkyway/pkg/strutils"
	"github.com/polite007/Milkyway/static"
	"golang.org/x/net/proxy"
	"gopkg.in/yaml.v3"
)

var (
	PocsList        []*templates.Template
	ExecuterOptions *protocols.ExecuterOptions
)

// 为httpx库设置代理
func InitHttpProxy() error {
	configs := config.Get()
	if configs.Socks5Proxy != "" {
		return httpx.WithProxy(configs.Socks5Proxy)
	}
	if configs.HttpProxy != "" {
		return httpx.WithProxy(configs.HttpProxy)
	}
	return nil
}

// 为nuclei poc引擎初始化，扫描漏洞前必须进行的
func InitPocEngine() error {
	// fmt.Printf("[*] 初始化poc库\n")
	if err := initNucleiPocList("poc_all"); err != nil {
		return err
	}
	return initNculeiProxy()
}

func initNucleiPocList(dir string) error {
	var (
		configs = config.Get()
		pocFile [][]byte
		err     error
	)
	if configs.PocFile != "" {
		pocFile, err = fileutils.ReadFilesFromDir(configs.PocFile)
		if err != nil {
			return err
		}
	} else {
		pocFile, err = fileutils.ReadFilesFromEmbedFs(static.EmbedFS, dir)
		if err != nil {
			return err
		}
	}

	if configs.PocId != "" {
		var configsPocids sync.Map
		for _, pocId := range strings.Split(configs.PocId, ",") {
			configsPocids.Store(pocId, true)
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
			if _, ok := configsPocids.Load(t.Id); ok {
				PocsList = append(PocsList, t)
			}
		}
		return nil
	}

	if configs.PocTags != "" {
		pocTags := strings.Split(configs.PocTags, ",")
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

			if strutils.HasCommonElement(pocTags, t.GetTags()) {
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
	fmt.Printf("[*] 当前poc库漏洞数: %d\n", len(PocsList))

	return nil
}

func initNculeiProxy() error {
	var (
		configs = config.Get()
	)
	if configs.HttpProxy != "" {
		Url, err := url.Parse(configs.HttpProxy)
		if err != nil {
			return err
		}
		http2.DefaultTransport.Proxy = http.ProxyURL(Url)
		return nil
	}

	if configs.Socks5Proxy != "" {
		Dail := &net.Dialer{
			Timeout:   5 * time.Second,
			KeepAlive: 5 * time.Second,
		}
		socks5Proxy, err := proxy2.Socks5Dailer(Dail)
		if err != nil {
			return err
		}
		if contextDialer, ok := socks5Proxy.(proxy.ContextDialer); ok {
			http2.DefaultTransport.DialContext = contextDialer.DialContext
			//Client.Transport = defaultTransport
			return nil
		} else {
			return errors.New("Failed type assertion to DialContext")
		}
	}
	return nil
}
