package libhttp

import (
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

type httpResult struct {
	Url        string
	Header     map[string][]string
	Server     string
	Body       string
	StatusCode int
	Length     int
	Title      string
	JsUrl      []string
	FavHash    string
}

func extractValue(regRule string, body string) ([][]string, error) {
	re := regexp.MustCompile(regRule)
	if re.MatchString(body) {
		return re.FindAllStringSubmatch(body, -1), nil
	} else {
		return nil, fmt.Errorf("no match")
	}
}

func getTitle(httpBody string) string {
	title, err := extractValue("<title>(.*?)</title>", httpBody)
	if err != nil {
		return "Not found"
	} else {
		return title[0][1]
	}
}

func getJsUrl(httpBody string) []string {
	regRules := []string{`<script.*?src="(.*?)"[^>]*>`}
	var jsUrlList []string
	for _, regRule := range regRules {
		jsUrls, err := extractValue(regRule, httpBody)
		if err != nil {
			continue
		}
		for _, jsUrl := range jsUrls {
			if strings.Contains(jsUrl[1], "http") {
				continue
			}
			if jsUrl[1][len(jsUrl)-1:] != "/" {
				jsUrlList = append(jsUrlList, "/"+jsUrl[1])
				continue
			}
			jsUrlList = append(jsUrlList, jsUrl[1])
		}
	}
	return nil
}

func getFavHash(httpBody string, httpUrl string) string {
	favPaths, err := extractValue(`href="(.*?favicon.*?)"`, httpBody)
	var favpath string
	if err != nil {
		return ""
	}
	u, err := url.Parse(httpUrl)
	if err != nil {
		panic(err)
	}
	httpUrl = u.Scheme + "://" + u.Host
	if len(favPaths) > 0 {
		fav := favPaths[0][1]
		if fav[:2] == "//" {
			favpath = "http:" + fav
		} else {
			if fav[:4] == "http" {
				favpath = fav
			} else {
				favpath = httpUrl + "/" + fav
			}
		}
	} else {
		favpath = httpUrl + "/favicon.ico"
	}
	return favicohash(favpath)
}

func HttpRequest(httpUrl string, httpProxy string) (*httpResult, error) {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	if httpProxy != "" {
		proxys := func(_ *http.Request) (*url.URL, error) {
			return url.Parse(httpProxy)
		}
		transport = &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			Proxy:           proxys,
		}
	}
	client := &http.Client{
		Timeout:   10 * time.Second,
		Transport: transport,
	}
	req, err := http.NewRequest("GET", httpUrl, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "*/*;q=0.8")
	req.Header.Set("Connection", "close")
	req.Header.Set("User-Agent", getRandomUserAgent())
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	bodyRaw, _ := io.ReadAll(resp.Body)
	bodyNew := toUtf8(string(bodyRaw), strings.ToLower(resp.Header.Get("Content-Type")))
	title := getTitle(bodyNew)
	header := resp.Header
	var server string
	serverName, ok := header["Server"]
	if ok {
		server = serverName[0]
	} else {
		Powered, ok := header["X-Powered-By"]
		if ok {
			server = Powered[0]
		} else {
			server = "None"
		}
	}
	favHash := getFavHash(bodyNew, httpUrl)
	jsUrl := getJsUrl(bodyNew)
	result := httpResult{httpUrl, header, server, bodyNew, resp.StatusCode, len(bodyNew), title, jsUrl, favHash}
	return &result, nil
}
