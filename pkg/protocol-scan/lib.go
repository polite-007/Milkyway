package protocol_scan

import (
	"fmt"
	"io"
	"net"
)

// readDataSmb 从TCP连接中读取SMB数据
func readDataSmb(conn net.Conn) ([]byte, error) {
	var bufAll []byte
	var smbFirst = make([]byte, 4)
	_, err := io.ReadFull(conn, smbFirst)
	if err == io.EOF {
		return nil, fmt.Errorf("no data on tcp or premature EOF")
	} else if err != nil {
		return nil, err
	}
	bufAll = append(bufAll, smbFirst...)
	smbTwo := make([]byte, bytesToInt(smbFirst))
	if _, err := io.ReadFull(conn, smbTwo); err != nil {
		return nil, fmt.Errorf("reading smb content: %w", err)
	}
	bufAll = append(bufAll, smbTwo...)
	return bufAll, nil
}

// readDataLdap 从TCP连接中读取LDAP数据
func readDataLdap(conn net.Conn) ([]byte, error) {
	var bufAll []byte
	var ldapFirst = make([]byte, 2)
	if _, err := io.ReadFull(conn, ldapFirst); err != nil {
		return nil, fmt.Errorf("reading err: %w", err)
	}
	ldapNumber := int(ldapFirst[1]) - 48
	var ldapTwoLen int
	if ldapNumber >= 81 && ldapNumber <= 89 {
		var ldapTwo = make([]byte, ldapNumber-80)
		_, err := io.ReadFull(conn, ldapTwo)
		if err != nil {
			return nil, err
		}
		ldapTwoLen = bytesToInt(ldapTwo)
		bufAll = append(bufAll, ldapFirst...)
		bufAll = append(bufAll, ldapTwo...)
	} else if ldapNumber < 81 {
		ldapTwoLen = int(bytesToInt(ldapFirst[1:]))
		bufAll = append(bufAll, ldapFirst...)
	} else {
		return nil, fmt.Errorf("invalid LDAP packet length: 0x%x", ldapFirst[1])
	}
	var ldapThree = make([]byte, ldapTwoLen)
	if _, err := io.ReadFull(conn, ldapThree); err != nil {
		return nil, fmt.Errorf("reading LDAP content: %w", err)
	}
	bufAll = append(bufAll, ldapThree...)
	return bufAll, nil
}

// 判断是否为可打印字符
func isPrintableInfo(bytes []byte) string {
	str := ""
	for _, b := range bytes {
		if b >= 32 && b <= 126 {
			str += fmt.Sprintf("%c", b)
		} else {
			str += fmt.Sprintf("\\x%02X", b)
		}
	}
	return str
}

// 将字节数组转换为整数
func bytesToInt(b []byte) int {
	var result uint64
	for _, byteVal := range b {
		result = (result << 8) | uint64(byteVal)
	}
	return int(result)
}
