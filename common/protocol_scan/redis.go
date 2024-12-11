package protocol_scan

import (
	"encoding/hex"
	"fmt"
	"github.com/polite007/Milkyway/common/proxy"
	"time"
)

func RedisScan(addr string) (string, error) {
	var (
		payload = "2a310d0a24340d0a696e666f0d0a"
	)
	conn, err := proxy.WrapperTCP("tcp", addr, 5*time.Second)
	if err == nil {
		defer conn.Close()
		requestPayload, _ := hex.DecodeString(payload)
		if _, err = conn.Write(requestPayload); err != nil {
			return "", err
		}
		resp, err := readDataRedis(conn)
		if err != nil {
			return "", err
		}
		return fmt.Sprintf("%s", string(resp[7:len(resp)-1])), nil
	} else {
		return "", err
	}
}
