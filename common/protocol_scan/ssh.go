package protocol_scan

import (
	"fmt"
	"github.com/polite007/Milkyway/common/proxy"
	"time"
)

func SshScan(addr string) (string, error) {
	conn, err := proxy.WrapperTCP("tcp", addr, 5*time.Second)
	if err == nil {
		defer conn.Close()
		resp, err := ReadDataSsh(conn)
		if err != nil {
			return "", err
		}
		return fmt.Sprintf("%s", string(resp)), nil
	} else {
		return "", err
	}
}
