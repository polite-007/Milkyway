package protocol_scan

import (
	"fmt"
	"github.com/polite007/Milkyway/common/proxy"
	"time"
)

func VncScan(addr string) (string, error) {
	conn, err := proxy.WrapperTCP("tcp", addr, 5*time.Second)
	if err == nil {
		defer conn.Close()
		resp, err := ReadDataVnc(conn)
		if err != nil {
			return "", err
		}
		return fmt.Sprintf("Version: %s", string(resp[3:len(resp)-1])), nil
	} else {
		return "", err
	}
}