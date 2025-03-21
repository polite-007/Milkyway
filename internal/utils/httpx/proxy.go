package httpx

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"

	proxy2 "github.com/polite007/Milkyway/internal/utils/proxy"
	"golang.org/x/net/proxy"
)

// WithProxy 为httpx库设置代理
func WithProxy(strProxy string) error {
	proxyURL, err := url.Parse(strProxy)
	if err != nil {
		return fmt.Errorf("代理地址解析失败: %v", err)
	}
	switch proxyURL.Scheme {
	case "http":
		defaultTransport.Proxy = http.ProxyURL(proxyURL)
		client.Transport = defaultTransport
		//fmt.Println("Using HTTP proxy:", strProxy)
		return nil
	case "socks5":
		socks5Proxy, err := proxy2.Socks5Dailer(dialer)
		if err != nil {
			return fmt.Errorf("代理地址解析失败: %v", err)
		}
		if contextDialer, ok := socks5Proxy.(proxy.ContextDialer); ok {
			defaultTransport.DialContext = contextDialer.DialContext
			client.Transport = defaultTransport
			//fmt.Println("Using SOCKS5 proxy:", strProxy)
			return nil
		} else {
			return errors.New("Failed type assertion to DialContext")
		}
	}
	return fmt.Errorf("不支持的代理类型: %s", proxyURL.Scheme)
}
