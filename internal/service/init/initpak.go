package initpak

import (
	"errors"
	"fmt"
	"github.com/polite007/Milkyway/internal/config"
	"github.com/polite007/Milkyway/internal/pkg/httpx"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	proxy2 "github.com/polite007/Milkyway/internal/pkg/network"
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
	PocsList       []*templates.Template
	ExecuteOptions *protocols.ExecuterOptions
)

// initNucleiPocList 初始化nuclei poc列表
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
		var configsPocIDs sync.Map
		for _, pocId := range strings.Split(configs.PocId, ",") {
			configsPocIDs.Store(pocId, true)
		}
		for _, poc := range pocFile {
			t := &templates.Template{}
			err = yaml.Unmarshal(poc, t)
			if err != nil {
				continue
			}
			err = t.Compile(ExecuteOptions)
			if err != nil {
				continue
			}
			if _, ok := configsPocIDs.Load(t.Id); ok {
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
			err = t.Compile(ExecuteOptions)
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
		err = t.Compile(ExecuteOptions)
		if err != nil {
			continue
		}
		PocsList = append(PocsList, t)
	}
	fmt.Printf("[*] 当前poc库漏洞数: %d\n", len(PocsList))

	return nil
}

// initNucleiProxy 初始化nuclei代理
func initNucleiProxy() error {
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

// InitHttpProxy 为httpx库设置代理
func InitHttpProxy(socks5Proxy, httpProxy string) error {
	if socks5Proxy != "" {
		return httpx.WithProxy(socks5Proxy)
	}
	if httpProxy != "" {
		return httpx.WithProxy(httpProxy)
	}
	return nil
}

// InitPocEngine 为nuclei poc引擎初始化，扫描漏洞前必须进行的
func InitPocEngine() error {
	// fmt.Printf("[*] 初始化poc库\n")
	if err := initNucleiPocList("poc_all"); err != nil {
		return err
	}
	return initNucleiProxy()
}
