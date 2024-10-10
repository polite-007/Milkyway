package network

import (
	"fmt"
	"testing"
)

func TestHttp(t *testing.T) {
	err := WithHttpProxy("socks5://127.0.0.1:7895")
	if err != nil {
		t.Fatal(err)
	}
	res, err := Get("http://www.hhtc.edu.cn", "/")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := HandleResponse(res)
	fmt.Println(body)
}
