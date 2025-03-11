package protocol_scan

import (
	"fmt"
	"time"

	"github.com/polite007/Milkyway/internal/service/pact/protocol_scan/lib"
	"github.com/polite007/Milkyway/internal/utils/proxy"
)

func VncScan(addr string) (string, error) {
	conn, err := proxy.WrapperTCP("tcp", addr, 5*time.Second)
	if err == nil {
		defer conn.Close()
		resp, err := lib.ReadDataVnc(conn)
		if err != nil {
			return "", err
		}
		return fmt.Sprintf("Version: %s", string(resp[3:len(resp)-1])), nil
	} else {
		return "", err
	}
}
