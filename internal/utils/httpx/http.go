package httpx

import (
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/polite007/Milkyway/config"
	"golang.org/x/net/html"
)

var (
	dialTimout = 5 * time.Second
	keepAlive  = 5 * time.Second
	dialer     = &net.Dialer{
		Timeout:   dialTimout,
		KeepAlive: keepAlive,
	}
)

var client = &http.Client{
	Transport: defaultTransport,
	Timeout:   config.Get().WebScanTimeout,
}

var defaultTransport = &http.Transport{
	DialContext:         dialer.DialContext,
	MaxConnsPerHost:     5,
	MaxIdleConns:        0,
	MaxIdleConnsPerHost: config.Get().WorkPoolNum,
	IdleConnTimeout:     keepAlive,
	TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS10, InsecureSkipVerify: true},
	TLSHandshakeTimeout: config.Get().TLSHandshakeTimeout,
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
	if err != nil {
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

type Resps struct {
	Url        *url.URL
	Title      string
	Body       string
	Header     map[string][]string
	Server     string
	StatusCode int
	FavHash    string
	Cms        string
	Tags       []string
}

func HandleResponse(resp *http.Response) (*Resps, error) {
	defer resp.Body.Close()
	// 读取响应体
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("读取响应体失败: %v", err)
	}

	//将响应体转换为UTF-8编码
	contentType := strings.ToLower(resp.Header.Get("Content-Type"))
	httpbody := toUtf8(string(body), contentType)

	//拿取标题
	doc, err := html.Parse(strings.NewReader(httpbody))
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
	favhash := getfavicon(httpbody, resp.Request.URL.String())

	// 返回结果
	return &Resps{
		Url:        resp.Request.URL,
		Title:      title,
		Body:       httpbody,
		Header:     resp.Header,
		Server:     server,
		StatusCode: resp.StatusCode,
		FavHash:    favhash,
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
