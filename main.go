package main

import (
	"Milkyway/libhttp"
	"fmt"
)

func main() {
	resp, err := libhttp.HttpRequest("https://www.deepl.com/", "http://127.0.0.1:8080")
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println(resp.FavHash)
}
