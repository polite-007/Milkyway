package protocol_scan

import (
	"time"

	"github.com/polite007/Milkyway/internal/service/pact/protocol_scan/lib"
	"github.com/polite007/Milkyway/internal/utils/proxy"
)

func SmtpScan(addr string) (string, error) {
	conn, err := proxy.WrapperTCP("tcp", addr, 5*time.Second)
	if err == nil {
		defer conn.Close()
		resp, err := lib.ReadDataNormal(conn)
		if err != nil {
			return "", err
		}
		content := string(resp)
		if len(content) >= 3 {
			if lib.IsInt(content[0:3]) {
				return content[3 : len(content)-1], nil
			} else {
				return "", lib.ErrNoCurrProtocol
			}
		} else {
			return "", lib.ErrNotEnoughSize
		}
	} else {
		return "", err
	}
}
