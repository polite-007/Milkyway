package network

import (
	"crypto/tls"
	"fmt"
	"golang.org/x/net/html"
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

type resps struct {
	Title      string
	Body       string
	Header     map[string][]string
	Server     string
	StatusCode int
	FavHash    string
}

func HandleResponse(resp *http.Response) (*resps, error) {
	defer resp.Body.Close()
	// 读取响应体
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("读取响应体失败: %v", err)
	}

	//拿取标题
	doc, err := html.Parse(strings.NewReader(string(body)))
	if err != nil {
		return nil, fmt.Errorf("Error parsing HTML: %v\n", err)
	}
	title := extractTitle(doc)

	//将响应体转换为UTF-8编码
	contentType := strings.ToLower(resp.Header.Get("Content-Type"))
	httpbody := toUtf8(string(body), contentType)

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

	return &resps{
		Title:      title,
		Body:       httpbody,
		Header:     resp.Header,
		Server:     server,
		StatusCode: resp.StatusCode,
		FavHash:    "",
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
	return title
}
