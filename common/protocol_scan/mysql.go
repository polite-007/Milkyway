package protocol_scan

import (
	"fmt"
	_const "github.com/polite007/Milkyway/common/const"
	"github.com/polite007/Milkyway/common/proxy"
)

func MysqlScan(addr string) (string, error) {
	conn, err := proxy.WrapperTCP("tcp", addr, _const.PortScanTimeout)
	if err == nil {
		defer conn.Close()
		resp, err := readDataMysql(conn)
		if err != nil {
			return "", err
		}
		length := len(resp)
		if len(resp) <= 56 {
			return fmt.Sprintf("Version: %s\nServer Language: %d\nAuthentication Plugin: %s\n", resp[5:11], bytesToInt(resp[27:28]), string(resp[50:length-1])), nil
		} else {
			return fmt.Sprintf("Version: %s\nServer Language: %d\nAuthentication Plugin: %s\n", resp[5:11], bytesToInt(resp[27:28]), string(resp[56:length-1])), nil
		}
	} else {
		return "", err
	}
}
