package protocol_vul

import (
	"fmt"

	"github.com/mitchellh/go-vnc"
	"github.com/polite007/Milkyway/config"
	"github.com/polite007/Milkyway/internal/pkg/proxy"
	"github.com/polite007/Milkyway/pkg/color"
	"github.com/polite007/Milkyway/pkg/logger"
)

func vncConn(ip string, port int, pass string) error {
	configs := &vnc.ClientConfig{
		Auth: []vnc.ClientAuth{
			&vnc.PasswordAuth{
				Password: pass,
			},
		},
	}
	conn, err := proxy.WrapperTCP("tcp", fmt.Sprintf("%s:%v", ip, port), config.Get().PortScanTimeout)
	if err != nil {
		return err
	}
	client, err := vnc.Client(conn, configs)
	if err == nil {
		defer client.Close()
		result := fmt.Sprintf("[%s] %v:%v password:%v\n", color.Red("vnc"), ip, port, color.Red(pass))
		logger.OutLog(result)
		config.Get().Result.AddProtocolVul(ip, port, "vnc", fmt.Sprintf("%v", pass))
	}
	return nil
}

func vncScan(ip string, port int) {
	for _, pass := range config.GetDict().PasswordVnc {
		if err := vncConn(ip, port, pass); err == nil {
			return
		}
	}
}
