package protocol_scan

import (
	"github.com/polite007/Milkyway/internal/service/connx"
	"github.com/polite007/Milkyway/internal/service/pact/protocol_scan/lib"
	"time"
)

func SmtpScan(addr string) (string, error) {
	conn, err := connx.WrapperTCP("tcp", addr, 5*time.Second)
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
