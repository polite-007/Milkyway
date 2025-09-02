package protocol_scan

import (
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/polite007/Milkyway/config"
	"github.com/polite007/Milkyway/internal/pkg/proxy"
	"github.com/polite007/Milkyway/pkg/color"
	"github.com/polite007/Milkyway/pkg/logger"
)

// PortScan 端口扫描,
// 扫描端口，返回协议名称和是否存活
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
		protocol, result, err = protocolScan(host, port)
		if err == nil && result != "" {
			if config.Get().Verbose {
				logOut := fmt.Sprintf("[*] [%s] %s:%d \n%s\n", color.Green(protocol), host, port, color.Green(strings.TrimSpace(result)))
				logger.OutLog(logOut)
			} else {
				logOut := fmt.Sprintf("[*] [%s] %s:%d\n", color.Green(protocol), host, port)
				logger.OutLog(logOut)
			}
			return protocol, true
		} else {
			logOut := fmt.Sprintf("[*] [unkonwn] %s:%d\n", host, port)
			logger.OutLog(logOut)
			return "", true
		}
	} else {
		return "", false
	}
}

func protocolScan(host string, port int) (string, string, error) {
	if config.Get().FullScan {
		// ssh
		if result, err := SshScan(makeAddr(host, port)); err == nil {
			return "ssh", result, nil
		}
		// mysql
		if result, err := MysqlScan(makeAddr(host, port)); err == nil {
			return "mysql", result, nil
		}
		// smb
		if result, err := SmbOsDiscoveryScan(makeAddr(host, port)); err == nil {
			return "smb", result, nil
		}
		// redis
		if result, err := RedisScan(makeAddr(host, port)); err == nil {
			return "redis", result, nil
		}
		// ldap
		if result, err := LdapRootDseScan(makeAddr(host, port)); err == nil {
			return "ldap", result, nil
		}
		// smtp
		if result, err := SmtpScan(makeAddr(host, port)); err == nil {
			return "smtp", result, nil
		}
		// vnc
		if result, err := VncScan(makeAddr(host, port)); err == nil {
			return "vnc", result, nil
		}
		// rdp
		if result, err := RdpScan(makeAddr(host, port)); err == nil {
			return "rdp", result, nil
		}
		// ftp
		if result, err := FtpScan(makeAddr(host, port)); err == nil {
			return "ftp", result, nil
		}
		// null
		return "", "", config.GetErrors().ErrPortocolScanFailed
	} else {
		var (
			protocol string
			ok       bool
		)
		if protocol, ok = config.GetPorts().PortGroupMapNew[port]; !ok {
			return "", "", config.GetErrors().ErrPortNotProtocol
		}
		switch protocol {
		case "rdp":
			if result, err := RdpScan(makeAddr(host, port)); err == nil {
				return protocol, result, nil
			} else {
				return "", "", err
			}
		case "ftp":
			if result, err := FtpScan(makeAddr(host, port)); err == nil {
				return protocol, result, nil
			} else {
				return "", "", err
			}
		case "ssh":
			if result, err := SshScan(makeAddr(host, port)); err == nil {
				return protocol, result, nil
			} else {
				return "", "", err
			}
		case "smtp":
			if result, err := SmtpScan(makeAddr(host, port)); err == nil {
				return protocol, result, nil
			} else {
				return "", "", err
			}
		case "smb":
			if result, err := SmbOsDiscoveryScan(makeAddr(host, port)); err == nil {
				return protocol, result, nil
			}
			if result, err := SmbProtocolScan(makeAddr(host, port)); err == nil {
				return protocol, result, nil
			} else {
				return "", "", err
			}
		case "ldap":
			if result, err := LdapRootDseScan(makeAddr(host, port)); err == nil {
				return protocol, result, nil
			} else {
				return "", "", err
			}
		case "mysql":
			if result, err := MysqlScan(makeAddr(host, port)); err == nil {
				return protocol, result, nil
			} else {
				return "", "", err
			}
		case "redis":
			if result, err := RedisScan(makeAddr(host, port)); err == nil {
				return protocol, result, nil
			} else {
				return "", "", err
			}
		case "vnc":
			if result, err := VncScan(makeAddr(host, port)); err == nil {
				return protocol, result, nil
			} else {
				return "", "", err
			}
		}
		return "", "", config.GetErrors().ErrPortNotProtocol
	}
}

func makeAddr(host string, port int) string {
	return fmt.Sprintf("%s:%d", host, port)
}
