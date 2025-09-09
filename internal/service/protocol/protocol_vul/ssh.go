package protocol_vul

import (
	"fmt"
	"github.com/polite007/Milkyway/internal/config"
	"net"
	"strings"

	"github.com/polite007/Milkyway/pkg/color"
	"github.com/polite007/Milkyway/pkg/logger"
	"golang.org/x/crypto/ssh"
)

func sshConn(ip string, port int, user string, pass string) error {
	Host, Port, Username, Password := ip, port, user, pass
	var Auth []ssh.AuthMethod
	if config.Get().SshKey != "" {
	} else {
		Auth = []ssh.AuthMethod{ssh.Password(Password)}
	}

	configs := &ssh.ClientConfig{
		User:    Username,
		Auth:    Auth,
		Timeout: config.Get().PortScanTimeout,
		HostKeyCallback: func(hostname string, remote net.Addr, key ssh.PublicKey) error {
			return nil
		},
	}

	client, err := ssh.Dial("tcp", fmt.Sprintf("%v:%v", Host, Port), configs)
	if err == nil {
		defer client.Close()
		session, err := client.NewSession()
		if err == nil {
			defer session.Close()
			var result string
			result = fmt.Sprintf("[%s] %v:%v %s:%s\n", color.Red("ssh"), Host, Port, color.Red(Username), color.Red(Password))
			logger.OutLog(result)
			config.GetAssetsResult().AddProtocolVul(ip, port, "ssh", fmt.Sprintf("%v:%v", Username, Password))
		}
		return nil
	} else {
		return err
	}
}

func sshScan(ip string, port int) {
	for _, user := range config.GetDict().UserSsh {
		for _, pass := range config.GetDict().PasswordSsh {
			pass = strings.Replace(pass, "{user}", user, -1)
			err := sshConn(ip, port, user, pass)
			if err == nil {
				return
			}
		}
	}
}
