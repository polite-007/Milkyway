package protocol_scan

import (
	"fmt"
	"github.com/polite007/Milkyway/common/proxy"
	"time"
)

func FtpScan(addr string) (string, error) {
	conn, err := proxy.WrapperTCP("tcp", addr, 5*time.Second)
	if err == nil {
		defer conn.Close()
		var resp []byte
		resp, err = ReadDataFtp(conn)
		if err != nil {
			return "", err
		}
		return fmt.Sprintf("%s", string(resp)), nil
	}
	return "", err
}