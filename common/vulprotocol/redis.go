package vulprotocol

import (
	"fmt"
	_const "github.com/polite007/Milkyway/common/const"
	"github.com/polite007/Milkyway/common/proxy"
	"github.com/polite007/Milkyway/pkg/log"
	"github.com/polite007/Milkyway/pkg/utils"
	"io"
	"net"
	"strings"
	"time"
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

func RedisConn(ip string, port int, pass string) error {
	realhost := fmt.Sprintf("%s:%v", ip, port)
	conn, err := proxy.WrapperTCP("tcp", realhost, _const.PortScanTimeout)
	if err != nil {
		return err
	}
	defer conn.Close()
	err = conn.SetReadDeadline(time.Now().Add(_const.PortScanTimeout))
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
			result := fmt.Sprintf("[%s] %s:%s\n", utils.Red("redis"), realhost, pass)
			log.OutLog(result)
		} else {
			result := fmt.Sprintf("[%s] %s:%s file:%s/%s\n", utils.Red("redis"), realhost, pass, dir, dbfilename)
			log.OutLog(result)
		}
		return nil
	}
	return err
}

func RedisUnauth(ip string, port int) error {
	realhost := fmt.Sprintf("%s:%v", ip, port)
	conn, err := proxy.WrapperTCP("tcp", realhost, _const.PortScanTimeout)
	if err != nil {
		return err
	}
	defer conn.Close()
	err = conn.SetReadDeadline(time.Now().Add(_const.PortScanTimeout))
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
			result := fmt.Sprintf("[%s] %s:%v %s\n", utils.Red("redis"), ip, port, utils.Red("unauthorized"))
			log.OutLog(result)
		} else {
			result := fmt.Sprintf("[%s] %s:%v %s:%s\n", utils.Red("redis"), ip, port, utils.Red("unauthorized file"), utils.Red(dir+"/"+dbfilename))
			log.OutLog(result)
		}
		return nil
	} else {
		return err
	}
}

func RedisScan(ip string, port int) {
	err := RedisUnauth(ip, port)
	if err == nil {
		return
	}
	for _, pass := range _const.PasswordRedis {
		if err = RedisConn(ip, port, pass); err == nil {
			return
		}
	}
}
