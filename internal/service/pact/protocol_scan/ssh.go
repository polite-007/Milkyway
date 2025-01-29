package protocol_scan

import (
	"fmt"
	"github.com/polite007/Milkyway/internal/service/connx"
	"github.com/polite007/Milkyway/internal/service/pact/protocol_scan/lib"
	"time"
)

func SshScan(addr string) (string, error) {
	conn, err := connx.WrapperTCP("tcp", addr, 5*time.Second)
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
