package protocol_scan

import (
	"fmt"
	"time"

	"github.com/polite007/Milkyway/internal/service/protocol_scan_vul/protocol_scan/lib"
	"github.com/polite007/Milkyway/internal/utils/proxy"
)

func SshScan(addr string) (string, error) {
	conn, err := proxy.WrapperTCP("tcp", addr, 5*time.Second)
	if err == nil {
		defer conn.Close()
		resp, err := lib.ReadDataSsh(conn)
		if err != nil {
			return "", err
		}
		return fmt.Sprintf("%s", string(resp)), nil
	} else {
		return "", err
	}
}
