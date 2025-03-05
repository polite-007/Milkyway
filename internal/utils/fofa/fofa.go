package fofa

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"github.com/polite007/Milkyway/pkg/strutils"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

type pagination struct {
	PageNum  int `json:"page_num" form:"page_num"`
	PageSize int `json:"page_size" form:"page_size"`
}

type FofaCore struct {
	FofaKey string
}

type fofaSearchConfig struct {
	pg     *pagination // 分页
	isFull bool        // 是否获取全部，默认只一年内的数据
	fields []string    // 返回字段
}

type hostResults struct {
	Mode    string     `json:"mode"`
	Error   bool       `json:"error"`
	Errmsg  string     `json:"errmsg"`
	Query   string     `json:"query"`
	Page    int        `json:"page"`
	Size    int        `json:"size"` // 总数
	Results [][]string `json:"results"`
	Next    string     `json:"next"`
}

var fofaCore *FofaCore

func GetFofaCore(fofaKey string) *FofaCore {
	if fofaCore == nil {
		fofaCore = &FofaCore{
			FofaKey: fofaKey,
		}
	}
	return fofaCore
}

func newFofaSearchConfig(opts ...func(*fofaSearchConfig)) *fofaSearchConfig {
	cfg := &fofaSearchConfig{
		pg: &pagination{
			PageNum:  1,
			PageSize: 10,
		},
		fields: []string{"ip", "port"},
	}
	for _, opt := range opts {
		opt(cfg)
	}

	if len(cfg.fields) == 0 {
		panic(errors.New("fofa search fields is empty"))
	}
	return cfg
}

func withFields(fields []string) func(*fofaSearchConfig) {
	return func(cfg *fofaSearchConfig) {
		cfg.fields = fields
	}
}

func withPagination(pg *pagination) func(*fofaSearchConfig) {
	return func(cfg *fofaSearchConfig) {
		cfg.pg = pg
	}
}

func (hr *hostResults) getIPs() []string {
	var ips []string
	for _, res := range hr.Results {
		ips = append(ips, res[0])
	}
	return ips
}

func (f *FofaCore) search(fofaQuery string, cfg *fofaSearchConfig) (*hostResults, error) {
	params := url.Values{}
	params.Set("qbase64", base64.StdEncoding.EncodeToString([]byte(fofaQuery)))
	params.Set("fields", strings.Join(cfg.fields, ","))
	params.Set("page", strconv.Itoa(cfg.pg.PageNum))
	params.Set("size", strconv.Itoa(cfg.pg.PageSize))
	if cfg.isFull {
		params.Add("full", "true")
	}
	params.Set("key", f.FofaKey)

	urlStr := "https://fofa.info/api/v1/search/all" + "?" + params.Encode()
	req, err := http.NewRequest(http.MethodGet, urlStr, nil)
	if err != nil {
		return nil, err
	}

	cli := http.Client{
		Transport: http.DefaultTransport,
		Timeout:   20 * time.Second,
	}

	resp, err := cli.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result hostResults
	if err = json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	return &result, nil
}

func isFofaErrorNeedPanic(errMsg string) error {
	if strings.HasPrefix(errMsg, "[811005]") {
		// [811005] 无效的fid值
		return nil
	} else if strings.HasPrefix(errMsg, "[811006]") {
		// [811006] 无效的sdk_hash值
		return nil
	} else if strings.HasPrefix(errMsg, "[820000]") {
		// [820000] 查询语法错误
		return nil
	} else if strings.HasPrefix(errMsg, "[811001]") {
		// [811001] 规则不存在
		return nil
	}
	return errors.New(errMsg)
}

func (f *FofaCore) StatsIP(fofaQuery string, size int) ([]string, error) {
	if size == 0 {
		// 默认查询1000条
		size = 1000
	}
	pg := &pagination{
		PageNum:  1,
		PageSize: size,
	}
	baseOpts := []func(*fofaSearchConfig){
		withFields([]string{"ip", "port"}),
		withPagination(pg),
	}

	var IPs []string
	for {
		time.Sleep(500 * time.Millisecond)
		cfg := newFofaSearchConfig(baseOpts...)
		hr, err := f.search(fofaQuery, cfg)
		if err != nil {
			continue
		}
		if hr.Error {
			if err = isFofaErrorNeedPanic(hr.Errmsg); err != nil {
				return nil, errors.New(hr.Errmsg)
			}
		}

		if hr.Size == 0 {
			break
		}

		IPs = append(IPs, hr.getIPs()...)
		if len(IPs) >= size {
			break
		}
		time.Sleep(500 * time.Millisecond)
		// 没有资产了
		if hr.Size < pg.PageNum*pg.PageSize {
			break
		}

		// 继续查询
		pg.PageNum++
		baseOpts = []func(*fofaSearchConfig){
			withFields([]string{"ip", "port"}),
			withPagination(pg),
		}
	}
	return strutils.RemoveDuplicateSliceString(IPs), nil
}
