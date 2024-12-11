package vulprotocol

import (
	"fmt"
	_const "github.com/polite007/Milkyway/common/const"
	"github.com/polite007/Milkyway/pkg/log"
	"github.com/polite007/Milkyway/pkg/utils"
	"golang.org/x/crypto/ssh"
	"net"
	"strings"
)

func SshConn(ip string, port int, user string, pass string) error {
	Host, Port, Username, Password := ip, port, user, pass
	var Auth []ssh.AuthMethod
	if _const.SshKey != "" {
	} else {
		Auth = []ssh.AuthMethod{ssh.Password(Password)}
	}

	config := &ssh.ClientConfig{
		User:    Username,
		Auth:    Auth,
		Timeout: _const.PortScanTimeout,
		HostKeyCallback: func(hostname string, remote net.Addr, key ssh.PublicKey) error {
			return nil
		},
	}

	client, err := ssh.Dial("tcp", fmt.Sprintf("%v:%v", Host, Port), config)
	if err == nil {
		defer client.Close()
		session, err := client.NewSession()
		if err == nil {
			defer session.Close()
			var result string
			result = fmt.Sprintf("[%s] %v:%v %s:%s\n", utils.Red("ssh"), Host, Port, utils.Red(Username), utils.Red(Password))
			log.OutLog(result)
		}
		return nil
	} else {
		return err
	}
}

func SshScan(ip string, port int) {
	for _, user := range _const.UserSsh {
		for _, pass := range _const.PasswordSsh {
			pass = strings.Replace(pass, "{user}", user, -1)
			err := SshConn(ip, port, user, pass)
			if err == nil {
				return
			}
		}
	}
}
