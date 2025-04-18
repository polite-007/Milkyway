package httpx

import (
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"hash"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"regexp"
	"time"

	"github.com/spaolacci/murmur3"
)

func getfavicon(httpbody string, turl string) string {
	faviconpaths := xegexpjs(`href="(.*?favicon....)"`, httpbody)
	var faviconpath string
	u, err := url.Parse(turl)
	if err != nil {
		panic(err)
	}
	turl = u.Scheme + "://" + u.Host
	if len(faviconpaths) > 0 {
		fav := faviconpaths[0][1]
		if fav[:2] == "//" {
			faviconpath = "http:" + fav
		} else {
			if fav[:4] == "http" {
				faviconpath = fav
			} else {
				faviconpath = turl + "/" + fav
			}

		}
	} else {
		faviconpath = turl + "/favicon.ico"
	}
	return favicohash(faviconpath)
}

func xegexpjs(reg string, resp string) (reslut1 [][]string) {
	reg1 := regexp.MustCompile(reg)
	if reg1 == nil {
		log.Println("regexp err")
		return nil
	}
	result1 := reg1.FindAllStringSubmatch(resp, -1)
	return result1
}

func favicohash(host string) string {
	timeout := time.Duration(8 * time.Second)
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := http.Client{
		Timeout:   timeout,
		Transport: tr,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse /* 不进入重定向 */
		},
	}
	resp, err := client.Get(host)
	if err != nil {
		//log.Println("favicon client error:", err)
		return "0"
	}
	defer resp.Body.Close()
	if resp.StatusCode == 200 {
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			//log.Println("favicon file read error: ", err)
			return "0"
		}
		return mmh3Hash32(standBase64(body))
	} else {
		return "0"
	}
}

func mmh3Hash32(raw []byte) string {
	var h32 hash.Hash32 = murmur3.New32()
	_, err := h32.Write([]byte(raw))
	if err == nil {
		return fmt.Sprintf("%d", int32(h32.Sum32()))
	} else {
		//log.Println("favicon Mmh3Hash32 error:", err)
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
