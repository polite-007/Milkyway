package protocol_scan

import (
	"fmt"

	"github.com/polite007/Milkyway/config"
	"github.com/polite007/Milkyway/internal/pkg/proxy"
	"github.com/polite007/Milkyway/internal/service/protocol/protocol_scan/lib"
)

func MysqlScan(addr string) (string, error) {
	conn, err := proxy.WrapperTCP("tcp", addr, config.Get().PortScanTimeout)
	if err == nil {
		defer conn.Close()
		resp, err := lib.ReadDataMysql(conn)
		if err != nil {
			return "", err
		}
		length := len(resp)
		if len(resp) <= 56 {
			return fmt.Sprintf("Version: %s\nServer Language: %d\nAuthentication Plugin: %s\n", resp[5:11], lib.BytesToInt(resp[27:28]), string(resp[50:length-1])), nil
		} else {
			return fmt.Sprintf("Version: %s\nServer Language: %d\nAuthentication Plugin: %s\n", resp[5:11], lib.BytesToInt(resp[27:28]), string(resp[56:length-1])), nil
		}
	} else {
		return "", err
	}
}
