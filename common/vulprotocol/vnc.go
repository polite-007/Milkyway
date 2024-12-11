package vulprotocol

import (
	"fmt"
	"github.com/mitchellh/go-vnc"
	_const "github.com/polite007/Milkyway/common/const"
	"github.com/polite007/Milkyway/common/proxy"
	"github.com/polite007/Milkyway/pkg/log"
	"github.com/polite007/Milkyway/pkg/utils"
)

func VncConn(ip string, port int, pass string) error {
	config := &vnc.ClientConfig{
		Auth: []vnc.ClientAuth{
			&vnc.PasswordAuth{
				Password: pass,
			},
		},
	}
	conn, err := proxy.WrapperTCP("tcp", fmt.Sprintf("%s:%v", ip, port), _const.PortScanTimeout)
	if err != nil {
		return err
	}
	client, err := vnc.Client(conn, config)
	if err == nil {
		defer client.Close()
		result := fmt.Sprintf("[%s] %v:%v password:%v\n", utils.Red("vnc"), ip, port, utils.Red(pass))
		log.OutLog(result)
	}
	return nil
}

func VncScan(ip string, port int) {
	for _, pass := range _const.PasswordVnc {
		if err := VncConn(ip, port, pass); err == nil {
			return
		}
	}
}
