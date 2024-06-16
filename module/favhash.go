package module

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"hash"
	"io"
	"net/http"
	"time"

	"github.com/twmb/murmur3"
)

func mmh3Hash32(raw []byte) string {
	var h32 hash.Hash32 = murmur3.New32()
	_, err := h32.Write([]byte(raw))
	if err == nil {
		return fmt.Sprintf("%d", int32(h32.Sum32()))
	} else {
		return "0"
	}
}

func standBase64(braw []byte) []byte {
	bckd := base64.StdEncoding.EncodeToString(braw)
	var buffer bytes.Buffer
	for i := 0; i < len(bckd); i++ {
		ch := bckd[i]
		buffer.WriteByte(ch)
		if (i+1)%76 == 0 {
			buffer.WriteByte('\n')
		}
	}
	buffer.WriteByte('\n')
	return buffer.Bytes()

}

func favicohash(host string, tr *http.Transport) string {
	timeout := time.Duration(8 * time.Second)
	client := http.Client{
		Timeout:   timeout,
		Transport: tr,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse //不进入重定向
		},
	}
	resp, err := client.Get(host)
	if err != nil {
		return "0"
	}
	defer resp.Body.Close()
	if resp.StatusCode == 200 {
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return "0"
		}
		return mmh3Hash32(standBase64(body))
	} else {
		return "0"
	}
}
