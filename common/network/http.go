package network

import (
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

var (
	dialTimout = 5 * time.Second
	keepAlive  = 5 * time.Second
	threadsNum = 50
	dialer     = &net.Dialer{
		Timeout:   dialTimout,
		KeepAlive: keepAlive,
	}
)

var client = &http.Client{
	Transport: defaultTransport,
	Timeout:   10 * time.Second,
}

var defaultTransport = &http.Transport{
	DialContext:         dialer.DialContext,
	MaxConnsPerHost:     5,
	MaxIdleConns:        0,
	MaxIdleConnsPerHost: threadsNum * 2,
	IdleConnTimeout:     keepAlive,
	TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS10, InsecureSkipVerify: true},
	TLSHandshakeTimeout: 5 * time.Second,
	DisableKeepAlives:   false,
}

func Get(host, path string) (*http.Response, error) {
	req, err := http.NewRequest("GET", host+path, nil)
	if err != nil {
		return nil, fmt.Errorf("创建HTTP请求失败: %v", err)
	}
	req.Header.Set("User-Agent", getRandomUserAgent())

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("请求失败: %v", err)
	}
	return resp, nil
}

func Post(host, path string, body string) (*http.Response, error) {
	req, err := http.NewRequest("POST", host+path, strings.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("创建HTTP请求失败: %v", err)
	}
	req.Header.Set("User-Agent", getRandomUserAgent())

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("请求失败: %v", err)
	}
	return resp, nil
}

func HandleResponse(resp *http.Response) (string, error) {
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("读取响应体失败: %v", err)
	}
	return string(body), nil
}
