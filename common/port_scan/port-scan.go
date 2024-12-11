package port_scan

import (
	"fmt"
	_const "github.com/polite007/Milkyway/common/const"
	"github.com/polite007/Milkyway/common/protocol_scan"
	"github.com/polite007/Milkyway/common/proxy"
	"github.com/polite007/Milkyway/pkg/log"
	"github.com/polite007/Milkyway/pkg/utils"
	"net"
	"strings"
	"time"
)

func PortScan(host string, port int, timeout time.Duration) (string, bool) {
	var (
		conn     net.Conn
		err      error
		result   string
		protocol string
	)
	conn, err = proxy.WrapperTCP("tcp4", fmt.Sprintf("%s:%v", host, port), timeout)
	if err == nil {
		defer conn.Close()
		protocol, result, err = ProtocolScan(host, port)
		if err == nil && result != "" {
			if _const.Verbose {
				logOut := fmt.Sprintf("[*] [%s] %s:%d \n%s\n", utils.Green(protocol), host, port, utils.Green(strings.TrimSpace(result)))
				log.OutLog(logOut)
			} else {
				logOut := fmt.Sprintf("[*] [%s] %s:%d\n", utils.Green(protocol), host, port)
				log.OutLog(logOut)
			}
			return protocol, true
		} else {
			logOut := fmt.Sprintf("[*] [unkonwn] %s:%d\n", host, port)
			log.OutLog(logOut)
			return "", true
		}
	} else {
		return "", false
	}
}

func ProtocolScan(host string, port int) (string, string, error) {
	if _const.FullScan {
		// ssh
		if result, err := protocol_scan.SshScan(makeAddr(host, port)); err == nil {
			return "ssh", result, nil
		}
		// mysql
		if result, err := protocol_scan.MysqlScan(makeAddr(host, port)); err == nil {
			return "mysql", result, nil
		}
		// smb
		if result, err := protocol_scan.SmbOsDiscoveryScan(makeAddr(host, port)); err == nil {
			return "smb", result, nil
		}
		// redis
		if result, err := protocol_scan.RedisScan(makeAddr(host, port)); err == nil {
			return "redis", result, nil
		}
		// ldap
		if result, err := protocol_scan.LdapRootDseScan(makeAddr(host, port)); err == nil {
			return "ldap", result, nil
		}
		// smtp
		if result, err := protocol_scan.SmtpScan(makeAddr(host, port)); err == nil {
			return "smtp", result, nil
		}
		// vnc
		if result, err := protocol_scan.VncScan(makeAddr(host, port)); err == nil {
			return "vnc", result, nil
		}
		// rdp
		if result, err := protocol_scan.RdpScan(makeAddr(host, port)); err == nil {
			return "rdp", result, nil
		}
		// ftp
		if result, err := protocol_scan.FtpScan(makeAddr(host, port)); err == nil {
			return "ftp", result, nil
		}
		// null
		return "", "", _const.ErrPortocolScanFailed
	} else {
		var (
			protocol string
			ok       bool
		)
		if protocol, ok = _const.PortGroupMapNew[port]; !ok {
			return "", "", _const.ErrPortNotProtocol
		}
		switch protocol {
		case "rdp":
			if result, err := protocol_scan.RdpScan(makeAddr(host, port)); err == nil {
				return protocol, result, nil
			} else {
				return "", "", err
			}
		case "ftp":
			if result, err := protocol_scan.FtpScan(makeAddr(host, port)); err == nil {
				return protocol, result, nil
			} else {
				return "", "", err
			}
		case "ssh":
			if result, err := protocol_scan.SshScan(makeAddr(host, port)); err == nil {
				return protocol, result, nil
			} else {
				return "", "", err
			}
		case "smtp":
			if result, err := protocol_scan.SmtpScan(makeAddr(host, port)); err == nil {
				return protocol, result, nil
			} else {
				return "", "", err
			}
		case "smb":
			if result, err := protocol_scan.SmbOsDiscoveryScan(makeAddr(host, port)); err == nil {
				return protocol, result, nil
			}
			if result, err := protocol_scan.SmbProtocolScan(makeAddr(host, port)); err == nil {
				return protocol, result, nil
			} else {
				return "", "", err
			}
		case "ldap":
			if result, err := protocol_scan.LdapRootDseScan(makeAddr(host, port)); err == nil {
				return protocol, result, nil
			} else {
				return "", "", err
			}
		case "mysql":
			if result, err := protocol_scan.MysqlScan(makeAddr(host, port)); err == nil {
				return protocol, result, nil
			} else {
				return "", "", err
			}
		case "redis":
			if result, err := protocol_scan.RedisScan(makeAddr(host, port)); err == nil {
				return protocol, result, nil
			} else {
				return "", "", err
			}
		case "vnc":
			if result, err := protocol_scan.VncScan(makeAddr(host, port)); err == nil {
				return protocol, result, nil
			} else {
				return "", "", err
			}
		}
		return "", "", _const.ErrPortNotProtocol
	}
}

func makeAddr(host string, port int) string {
	return fmt.Sprintf("%s:%d", host, port)
}
