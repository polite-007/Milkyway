package httpx

import (
	"crypto/tls"
	"fmt"
	config2 "github.com/polite007/Milkyway/internal/config"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"golang.org/x/net/html"
)

var (
	dialTimout = 7 * time.Second
	keepAlive  = 10 * time.Second
	dialer     = &net.Dialer{
		Timeout:   dialTimout,
		KeepAlive: keepAlive,
	}
)

var client = &http.Client{
	Transport: defaultTransport,
	Timeout:   config2.Get().WebScanTimeout,
}

var defaultTransport = &http.Transport{
	DialContext:         dialer.DialContext,
	MaxConnsPerHost:     config2.Get().WorkPoolNum,
	MaxIdleConns:        config2.Get().WorkPoolNum,
	MaxIdleConnsPerHost: config2.Get().WorkPoolNum,
	IdleConnTimeout:     keepAlive,
	TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS10, InsecureSkipVerify: true},
	TLSHandshakeTimeout: config2.Get().TLSHandshakeTimeout,
	DisableKeepAlives:   false,
}

func Get(host string, header map[string]string, path string) (*http.Response, error) {
	req, err := http.NewRequest("GET", host+path, nil)
	if err != nil {
		return nil, fmt.Errorf("创建HTTP请求失败: %v", err)
	}
	req.Header.Set("User-Agent", getRandomUserAgent())
	for i, v := range header {
		req.Header.Set(i, v)
	}
	resp, err := client.Do(req)
	if err != nil || resp == nil {
		return nil, fmt.Errorf("请求失败: %v", err)
	}
	return resp, nil
}

func Post(host string, header map[string]string, path string, body string) (*http.Response, error) {
	req, err := http.NewRequest("POST", host+path, strings.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("创建HTTP请求失败: %v", err)
	}
	req.Header.Set("User-Agent", getRandomUserAgent())
	for i, v := range header {
		req.Header.Set(i, v)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("请求失败: %v", err)
	}
	return resp, nil
}

func Put(host string, header map[string]string, path string, body string) (*http.Response, error) {
	req, err := http.NewRequest("PUT", host+path, strings.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("创建HTTP请求失败: %v", err)
	}
	req.Header.Set("User-Agent", getRandomUserAgent())
	for i, v := range header {
		req.Header.Set(i, v)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("请求失败: %v", err)
	}
	return resp, nil
}

func HandleResponse(resp *http.Response) (*config2.Resp, error) {
	defer resp.Body.Close()
	// 读取响应体
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("读取响应体失败: %v", err)
	}

	//将响应体转换为UTF-8编码
	contentType := strings.ToLower(resp.Header.Get("Content-Type"))
	httpBody := toUtf8(string(body), contentType)

	//拿取标题
	doc, err := html.Parse(strings.NewReader(httpBody))
	if err != nil {
		return nil, fmt.Errorf("Error parsing HTML: %v\n", err)
	}
	title := extractTitle(doc)
	if title == "" {
		title = "Null"
	}

	// 获取服务器信息
	var server string
	capital, ok := resp.Header["Server"]
	if ok {
		server = capital[0]
	} else {
		Powered, ok := resp.Header["X-Powered-By"]
		if ok {
			server = Powered[0]
		} else {
			server = "None"
		}
	}

	// 获取favicon哈希值
	favHash := getfavicon(httpBody, resp.Request.URL.String())

	// 返回结果
	return &config2.Resp{
		Url:        resp.Request.URL,
		Title:      title,
		Body:       httpBody,
		Header:     resp.Header,
		Server:     server,
		StatusCode: resp.StatusCode,
		FavHash:    favHash,
	}, nil
}

func extractTitle(body *html.Node) string {
	var title string
	var f func(*html.Node)
	f = func(n *html.Node) {
		if n.Type == html.ElementNode && n.Data == "title" {
			// 找到 title 节点，获取其子节点的文本内容
			for c := n.FirstChild; c != nil; c = c.NextSibling {
				if c.Type == html.TextNode {
					title = c.Data
				}
			}
		}
		// 递归遍历所有子节点
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			f(c)
		}
	}
	f(body)
	return strings.TrimSpace(title)
}
