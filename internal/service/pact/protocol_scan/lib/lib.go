package lib

import (
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"
)

var (
	ErrNotEnoughSize  = errors.New("no enough size")
	ErrNoCurrProtocol = errors.New("not current protocol")
)

var (
	timeout = 5 * time.Second
)

func ReadDataRedis(conn net.Conn) ([]byte, error) {
	var redisFirst = make([]byte, 7)
	if _, err := ReadWithTimeout(conn, redisFirst, timeout); err != nil {
		return nil, err
	}

	lengthTwo := ExtractAndConcatenateSecondDigit(redisFirst[1:5])
	redisTwo := make([]byte, lengthTwo)
	if _, err := ReadWithTimeout(conn, redisTwo, timeout); err != nil {
		return nil, err
	}
	return append(redisFirst, redisTwo...), nil
}

func ReadDataMysql(conn net.Conn) ([]byte, error) {
	var mysqlFirst = make([]byte, 4)
	if _, err := ReadWithTimeout(conn, mysqlFirst, timeout); err != nil {
		return nil, err
	}

	lengthTwo := BytesToInt(ReverseBytes(mysqlFirst[0:3]))
	mysqlTwo := make([]byte, lengthTwo)
	if _, err := ReadWithTimeout(conn, mysqlTwo, timeout); err != nil {
		return nil, err
	}
	return append(mysqlFirst, mysqlTwo...), nil
}

// ReadDataSmb 从TCP连接中读取SMB数据
func ReadDataSmb(conn net.Conn) (int, []byte, error) {
	var bufAll []byte
	var smbFirst = make([]byte, 4)
	_, err := ReadWithTimeout(conn, smbFirst, timeout)
	if err == io.EOF {
		return 0, nil, ErrNoCurrProtocol
	} else if err != nil {
		return 0, nil, err
	}
	bufAll = append(bufAll, smbFirst...)
	smbTwo := make([]byte, BytesToInt(smbFirst))
	if _, err = ReadWithTimeout(conn, smbTwo, timeout); err != nil {
		return 0, nil, err
	}
	bufAll = append(bufAll, smbTwo...)
	return len(bufAll), bufAll, nil
}

// ReadDataLdap 从TCP连接中读取LDAP数据
func ReadDataLdap(conn net.Conn) ([]byte, error) {
	var bufAll []byte
	var ldapFirst = make([]byte, 2)
	if _, err := ReadWithTimeout(conn, ldapFirst, timeout); err != nil {
		return nil, err
	}
	ldapNumber := int(ldapFirst[1]) - 48
	var ldapTwoLen int
	if ldapNumber >= 81 && ldapNumber <= 89 {
		var ldapTwo = make([]byte, ldapNumber-80)
		_, err := ReadWithTimeout(conn, ldapTwo, timeout)
		if err != nil {
			return nil, err
		}
		ldapTwoLen = BytesToInt(ldapTwo)
		bufAll = append(bufAll, ldapFirst...)
		bufAll = append(bufAll, ldapTwo...)
	} else if ldapNumber < 81 {
		ldapTwoLen = BytesToInt(ldapFirst[1:])
		bufAll = append(bufAll, ldapFirst...)
	} else {
		return nil, ErrNoCurrProtocol
	}
	var ldapThree = make([]byte, ldapTwoLen)
	if _, err := ReadWithTimeout(conn, ldapThree, timeout); err != nil {
		return nil, err
	}
	bufAll = append(bufAll, ldapThree...)
	return bufAll, nil
}

func ReadDataSsh(conn net.Conn) ([]byte, error) {
	ssh, err := ReadUntilCRLF(conn)
	if err != nil {
		return nil, err
	}
	if !strings.Contains(string(ssh), "SSH") {
		return nil, ErrNoCurrProtocol
	}
	return ssh, nil
}

func ReadDataFtp(conn net.Conn) ([]byte, error) {
	//var bufAll []byte
	var ftpFirst = make([]byte, 4)
	if _, err := ReadWithTimeout(conn, ftpFirst, timeout); err != nil {
		return nil, err
	}
	if string(ftpFirst[0:3]) != "220" {
		return nil, ErrNoCurrProtocol
	}

	ftpTwo, err := ReadUntilCRLF(conn)
	if err != nil {
		return nil, err
	}
	if !strings.Contains(string(ftpTwo), "FTP") {
		return nil, ErrNoCurrProtocol
	}
	return append(ftpFirst, ftpTwo...), nil
}

func ReadDataVnc(conn net.Conn) ([]byte, error) {
	//var bufAll []byte
	var VncFirst = make([]byte, 3)
	if _, err := ReadWithTimeout(conn, VncFirst, timeout); err != nil {
		return nil, err
	}
	if string(VncFirst) != "RFB" {
		return nil, ErrNoCurrProtocol
	}
	var VncTwo = make([]byte, 9)
	if _, err := ReadWithTimeout(conn, VncTwo, timeout); err != nil {
		return nil, err
	}
	return append(VncFirst, VncTwo...), nil
}

func ReadDataNormal(conn net.Conn) (result []byte, err error) {
	size := 16
	buf := make([]byte, size)
	for {
		count, err := ReadWithTimeout(conn, buf, timeout)
		if err != nil {
			break
		}
		result = append(result, buf[0:count]...)
		if count < size {
			break
		}
	}
	if len(result) > 0 {
		err = nil
	}
	return result, err
}

func ReadDataRdp(conn net.Conn) ([]byte, error) {
	var RdpFirst = make([]byte, 5)
	if _, err := ReadWithTimeout(conn, RdpFirst, timeout); err != nil {
		return nil, err
	}
	var RdpTwo = make([]byte, BytesToInt(RdpFirst[4:5]))
	if _, err := ReadWithTimeout(conn, RdpTwo, timeout); err != nil {
		return nil, err
	}
	return append(RdpFirst, RdpTwo...), nil
}

func ReadWithTimeout(conn net.Conn, buf []byte, timeout time.Duration) (int, error) {
	// 设置读取超时
	if err := conn.SetReadDeadline(time.Now().Add(timeout)); err != nil {
		return 0, err
	}

	// 使用 io.ReadFull 读取数据
	n, err := io.ReadFull(conn, buf)
	if err != nil {
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			return n, fmt.Errorf("读取超时: %w", err)
		}
		return n, err
	}
	if n != len(buf) {
		return n, ErrNoCurrProtocol
	}
	return n, nil
}

// 将字节数组转换为整数
func BytesToInt(b []byte) int {
	var result uint64
	for _, byteVal := range b {
		result = (result << 8) | uint64(byteVal)
	}
	return int(result)
}

func ReverseBytes(b []byte) []byte {
	for i, j := 0, len(b)-1; i < j; i, j = i+1, j-1 {
		b[i], b[j] = b[j], b[i]
	}
	return b
}

func ExtractAndConcatenateSecondDigit(bytes []byte) int {
	var result string
	for _, b := range bytes {
		str := fmt.Sprintf("%d", b)
		if len(str) >= 2 {
			result += string(str[1])
		}
	}
	finalResult, err := strconv.Atoi(result)
	if err != nil {
		panic(err)
	}
	return finalResult
}

func ReadUntilCRLF(conn net.Conn) ([]byte, error) {
	var result []byte
	buffer := make([]byte, 1)
	for {
		// 从连接中读取一个字节
		_, err := ReadWithTimeout(conn, buffer, timeout)
		if err != nil {
			if err == io.EOF {
				// 如果遇到 EOF 表示连接关闭
				return result, nil
			}
			return nil, fmt.Errorf("读取字节失败: %v", err)
		}
		// 如果遇到 0x0d (回车) 或 0x0a (换行)，停止读取
		if buffer[0] == 0x0d || buffer[0] == 0x0a {
			break
		}
		result = append(result, buffer[0])
	}
	return result, nil
}

func IsInt(str string) bool {
	for _, c := range str {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}
