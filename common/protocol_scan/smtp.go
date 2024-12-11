package protocol_scan

import (
	"github.com/polite007/Milkyway/common/proxy"
	"time"
)

func SmtpScan(addr string) (string, error) {
	conn, err := proxy.WrapperTCP("tcp", addr, 5*time.Second)
	if err == nil {
		defer conn.Close()
		resp, err := ReadDataNormal(conn)
		if err != nil {
			return "", err
		}
		content := string(resp)
		if len(content) >= 3 {
			if IsInt(content[0:3]) {
				return content[3 : len(content)-1], nil
			} else {
				return "", ErrNoCurrProtocol
			}
		} else {
			return "", ErrNotEnoughSize
		}
	} else {
		return "", err
	}
}

func IsInt(str string) bool {
	for _, c := range str {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}
