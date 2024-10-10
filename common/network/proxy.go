package network

import (
	"errors"
	"fmt"
	"golang.org/x/net/proxy"
	"net"
	"net/http"
	"net/url"
)

func WithHttpProxy(strProxy string) error {
	proxyURL, err := url.Parse(strProxy)
	if err != nil {
		return fmt.Errorf("代理地址解析失败: %v", err)
	}
	switch proxyURL.Scheme {
	case "http":
		defaultTransport.Proxy = http.ProxyURL(proxyURL)
		client.Transport = defaultTransport
		return nil
	case "socks5":
		socks5Proxy, err := socks5Dailer(proxyURL, dialer)
		if err != nil {
			return fmt.Errorf("代理地址解析失败: %v", err)
		}
		if contextDialer, ok := socks5Proxy.(proxy.ContextDialer); ok {
			defaultTransport.DialContext = contextDialer.DialContext
			client.Transport = defaultTransport
			return nil
		} else {
			return errors.New("Failed type assertion to DialContext")
		}
	}
	return fmt.Errorf("不支持的代理类型: %s", proxyURL.Scheme)
}

func socks5Dailer(u *url.URL, forward *net.Dialer) (proxy.Dialer, error) {
	address := u.Host
	var auth proxy.Auth
	var dailer proxy.Dialer
	var err error

	if u.User.String() != "" {
		auth = proxy.Auth{}
		auth.User = u.User.Username()
		password, _ := u.User.Password()
		auth.Password = password
		dailer, err = proxy.SOCKS5("tcp", address, &auth, forward)
	} else {
		dailer, err = proxy.SOCKS5("tcp", address, nil, forward)
	}

	if err != nil {
		return nil, err
	}
	return dailer, nil
}
