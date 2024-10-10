package main

import (
	"fmt"
	"github.com/polite007/Milkyway/common/network"
)

func main() {
	//cmd.Execute()
	_ = network.WithHttpProxy("socks5://127.0.0.1:7895")

	resp, err := network.Get("http://www.baidu.com", "")
	if err != nil {
		panic(err)
	}
	content, _ := network.HandleResponse(resp)
	fmt.Println(content)
}
