package protocol_vul

import (
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"github.com/polite007/Milkyway/config"
	"github.com/polite007/Milkyway/internal/utils/proxy"
	"github.com/polite007/Milkyway/pkg/color"
	"github.com/polite007/Milkyway/pkg/logger"
)

var (
	dbfilename string
	dir        string
)

func readreply(conn net.Conn) (string, error) {
	conn.SetReadDeadline(time.Now().Add(time.Second))
	bytes, err := io.ReadAll(conn)
	if len(bytes) > 0 {
		err = nil
	}
	return string(bytes), err
}

func getconfig(conn net.Conn) (dbfilename string, dir string, err error) {
	_, err = conn.Write([]byte("CONFIG GET dbfilename\r\n"))
	if err != nil {
		return
	}
	text, err := readreply(conn)
	if err != nil {
		return
	}
	text1 := strings.Split(text, "\r\n")
	if len(text1) > 2 {
		dbfilename = text1[len(text1)-2]
	} else {
		dbfilename = text1[0]
	}
	_, err = conn.Write([]byte("CONFIG GET dir\r\n"))
	if err != nil {
		return
	}
	text, err = readreply(conn)
	if err != nil {
		return
	}
	text1 = strings.Split(text, "\r\n")
	if len(text1) > 2 {
		dir = text1[len(text1)-2]
	} else {
		dir = text1[0]
	}
	return
}

func redisConn(ip string, port int, pass string) error {
	realhost := fmt.Sprintf("%s:%v", ip, port)
	conn, err := proxy.WrapperTCP("tcp", realhost, config.PortScanTimeout)
	if err != nil {
		return err
	}
	defer conn.Close()
	err = conn.SetReadDeadline(time.Now().Add(config.PortScanTimeout))
	if err != nil {
		return err
	}
	_, err = conn.Write([]byte(fmt.Sprintf("auth %s\r\n", pass)))
	if err != nil {
		return err
	}
	reply, err := readreply(conn)
	if err != nil {
		return err
	}
	if strings.Contains(reply, "+OK") {
		dbfilename, dir, err = getconfig(conn)
		if err != nil {
			result := fmt.Sprintf("[%s] %s:%s\n", color.Red("redis"), realhost, pass)
			logger.OutLog(result)
		} else {
			result := fmt.Sprintf("[%s] %s:%s file:%s/%s\n", color.Red("redis"), realhost, pass, dir, dbfilename)
			logger.OutLog(result)
		}
		return nil
	}
	return err
}

func redisUnauth(ip string, port int) error {
	realHost := fmt.Sprintf("%s:%v", ip, port)
	conn, err := proxy.WrapperTCP("tcp", realHost, config.PortScanTimeout)
	if err != nil {
		return err
	}
	defer conn.Close()
	err = conn.SetReadDeadline(time.Now().Add(config.PortScanTimeout))
	if err != nil {
		return err
	}
	_, err = conn.Write([]byte("info\r\n"))
	if err != nil {
		return err
	}
	reply, err := readreply(conn)
	if err != nil {
		return err
	}
	if strings.Contains(reply, "redis_version") {
		dbfilename, dir, err = getconfig(conn)
		if err != nil {
			result := fmt.Sprintf("[%s] %s:%v %s\n", color.Red("redis"), ip, port, color.Red("unauthorized"))
			logger.OutLog(result)
			config.Get().Vul.AddProtocolVul(ip, port, "redis", "unauthorized")
		} else {
			result := fmt.Sprintf("[%s] %s:%v %s:%s\n", color.Red("redis"), ip, port, color.Red("unauthorized file"), color.Red(dir+"/"+dbfilename))
			logger.OutLog(result)
			config.Get().Vul.AddProtocolVul(ip, port, "redis", fmt.Sprintf("%s", "unauthorized file: "+dir+"/"+dbfilename))
		}
		return nil
	} else {
		return err
	}
}

func redisScan(ip string, port int) {
	err := redisUnauth(ip, port)
	if err == nil {
		return
	}
	for _, pass := range config.GetDict().PasswordRedis {
		if err = redisConn(ip, port, pass); err == nil {
			return
		}
	}
}
