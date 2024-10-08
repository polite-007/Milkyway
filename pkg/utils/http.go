package utils

import (
	"bytes"
	"crypto/tls"
	"net/http"
	"net/url"
	"time"
)

type HttpClient struct {
	Timeout time.Duration
	Proxy   string
	Url     string
	Header  map[string]string
	Body    string
}

func (h *HttpClient) Get() (*http.Response, error) {
	req, err := http.NewRequest("GET", h.Url, nil)
	if err != nil {
		return nil, err
	}
	for key, value := range h.Header {
		req.Header.Set(key, value)
	}
	client := &http.Client{
		Timeout: h.Timeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
	if h.Proxy != "" {
		proxy, _ := url.Parse(h.Proxy)
		client = &http.Client{
			Timeout: h.Timeout,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
				Proxy:           http.ProxyURL(proxy),
			},
		}
	}
	return client.Do(req)
}

func (h *HttpClient) Post() (*http.Response, error) {
	req, err := http.NewRequest("POST", h.Url, bytes.NewBuffer([]byte(h.Body)))
	if err != nil {
		return nil, err
	}
	for key, value := range h.Header {
		req.Header.Set(key, value)
	}
	client := &http.Client{
		Timeout: h.Timeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
	if h.Proxy != "" {
		proxy, _ := url.Parse(h.Proxy)
		client = &http.Client{
			Timeout: h.Timeout,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
				Proxy:           http.ProxyURL(proxy),
			},
		}
	}
	return client.Do(req)
}
