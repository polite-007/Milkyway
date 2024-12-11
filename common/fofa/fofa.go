package fofa

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	_const "github.com/polite007/Milkyway/common/const"
	"github.com/polite007/Milkyway/pkg/utils"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

type Pagination struct {
	PageNum  int `json:"page_num" form:"page_num"`
	PageSize int `json:"page_size" form:"page_size"`
}

type FofaSearchConfig struct {
	pg     *Pagination // 分页
	isFull bool        // 是否获取全部，默认只一年内的数据
	fields []string    // 返回字段
}

type HostResults struct {
	Mode    string     `json:"mode"`
	Error   bool       `json:"error"`
	Errmsg  string     `json:"errmsg"`
	Query   string     `json:"query"`
	Page    int        `json:"page"`
	Size    int        `json:"size"` // 总数
	Results [][]string `json:"results"`
	Next    string     `json:"next"`
}

var (
	DumpFofaFields = []string{
		"ip",
		"port",
	}
)

func NewFofaSearchConfig(opts ...func(*FofaSearchConfig)) *FofaSearchConfig {
	cfg := &FofaSearchConfig{
		pg: &Pagination{
			PageNum:  1,
			PageSize: 10,
		},
		fields: DumpFofaFields,
	}
	for _, opt := range opts {
		opt(cfg)
	}

	if len(cfg.fields) == 0 {
		panic(errors.New("fofa search fields is empty"))
	}
	return cfg
}

func WithFields(fields []string) func(*FofaSearchConfig) {
	return func(cfg *FofaSearchConfig) {
		cfg.fields = fields
	}
}

func WithPagination(pg *Pagination) func(*FofaSearchConfig) {
	return func(cfg *FofaSearchConfig) {
		cfg.pg = pg
	}
}

func (hr *HostResults) GetIPs() []string {
	var ips []string
	for _, res := range hr.Results {
		ips = append(ips, res[0])
	}
	return ips
}

func Search(fofaQuery string, cfg *FofaSearchConfig) (*HostResults, error) {
	params := url.Values{}
	params.Set("qbase64", base64.StdEncoding.EncodeToString([]byte(fofaQuery)))
	params.Set("fields", strings.Join(cfg.fields, ","))
	params.Set("page", strconv.Itoa(cfg.pg.PageNum))
	params.Set("size", strconv.Itoa(cfg.pg.PageSize))
	if cfg.isFull {
		params.Add("full", "true")
	}
	params.Set("key", _const.FofaKey)

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

	var result HostResults
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
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

func StatsIP(fofaQuery string) ([]string, error) {
	// 基本配置
	fofasize := 1000
	if _const.FofaSize <= 1000 {
		fofasize = _const.FofaSize
	}
	pg := &Pagination{
		PageNum:  1,
		PageSize: fofasize,
	}
	baseOpts := []func(*FofaSearchConfig){
		WithFields([]string{"ip", "port"}),
		WithPagination(pg),
	}

	var IPs []string
	for {
		time.Sleep(500 * time.Millisecond)
		cfg := NewFofaSearchConfig(baseOpts...)
		hr, err := Search(fofaQuery, cfg)
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

		IPs = append(IPs, hr.GetIPs()...)
		if len(IPs) >= _const.FofaSize {
			break
		}
		time.Sleep(500 * time.Millisecond)
		// 没有资产了
		if hr.Size < pg.PageNum*pg.PageSize {
			break
		}

		// 继续查询
		pg.PageNum++
		baseOpts = []func(*FofaSearchConfig){
			WithFields([]string{"ip", "port"}),
			WithPagination(pg),
		}
	}
	return utils.RemoveDuplicateSliceString(IPs), nil
}
