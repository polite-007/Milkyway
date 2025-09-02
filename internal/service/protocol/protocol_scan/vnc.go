package protocol_scan

import (
	"fmt"
	"time"

	"github.com/polite007/Milkyway/internal/pkg/network"
	"github.com/polite007/Milkyway/internal/service/protocol/protocol_scan/lib"
)

func VncScan(addr string) (string, error) {
	conn, err := network.WrapperTCP("tcp", addr, 5*time.Second)
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
