package connx

import (
	"errors"
	"github.com/polite007/Milkyway/config"
	"golang.org/x/net/proxy"
	"net"
	"net/url"
	"strings"
	"time"
)

// WrapperTCP 获取一个TCP连接
func WrapperTCP(network, address string, timeout time.Duration) (net.Conn, error) {
	configs := config.Get()
	forward := &net.Dialer{Timeout: timeout}
	var conn net.Conn
	if configs.Socks5Proxy == "" {
		var err error
		conn, err = forward.Dial(network, address)
		if err != nil {
			return nil, err
		}
	} else {
		dailer, err := Socks5Dailer(forward)
		if err != nil {
			return nil, err
		}
		conn, err = dailer.Dial(network, address)
		if err != nil {
			return nil, err
		}
	}
	return conn, nil
}

func Socks5Dailer(forward *net.Dialer) (proxy.Dialer, error) {
	configs := config.Get()
	u, err := url.Parse(configs.Socks5Proxy)
	if err != nil {
		return nil, err
	}
	if strings.ToLower(u.Scheme) != "socks5" {
		return nil, errors.New("only support socks5")
	}
	address := u.Host
	var auth proxy.Auth
	var dailer proxy.Dialer
	if u.User.String() != "" {
		auth = proxy.Auth{}
		auth.User = u.User.Username()
		password, _ := u.User.Password()
		auth.Password = password
		dailer, err = proxy.SOCKS5("tcp", address, &auth, forward)
	} else {
		dailer, err = proxy.SOCKS5("tcp", address, nil, forward)
	}

	if err != nil {
		return nil, err
	}
	return dailer, nil
}
