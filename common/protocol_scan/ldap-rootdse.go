package protocol_scan

import (
	"fmt"
	"github.com/polite007/Milkyway/common/proxy"
	"github.com/polite007/Milkyway/pkg/utils"
	"strconv"
	"strings"
	"time"
)

func LdapRootDseScan(addr string) (string, error) {

	// 解析出LDAP的attributes数据
	obtainObject := func(data []byte) (string, []byte) {
		var cname string
		numberOne, _ := strconv.Atoi(fmt.Sprintf("%x", data[1]))
		if numberOne < 81 || numberOne > 89 {
			return "", data[4:]
		} else {
			data = data[numberOne-77:]
			length, _ := strconv.ParseInt(fmt.Sprintf("%x", data[0]), 16, 64)
			cname = fmt.Sprintf("%s", data[1:length+1])
			data = data[length+1:]
		}
		numberOne, _ = strconv.Atoi(fmt.Sprintf("%x", data[1]))
		if numberOne < 81 || numberOne > 89 {
			return "", data[4:]
		} else {
			return cname, data[numberOne-78:]
		}
	}

	// 解析出LDAP的type数据和vals
	obtainAttribute := func(data []byte) (string, []byte) {
		var content string

		numberOne, _ := strconv.Atoi(fmt.Sprintf("%x", data[1]))
		if numberOne < 81 || numberOne > 89 {
			data = data[3:]
		} else {
			data = data[numberOne-77:]
		}

		lengthType, _ := strconv.ParseInt(fmt.Sprintf("%x", data[0]), 16, 64)
		valueType := fmt.Sprintf("%s", data[1:lengthType+1])
		data = data[lengthType+1:]
		content = valueType + ":\n "
		if len(data) == 0 {
			return content, nil
		}
		numberOne, _ = strconv.Atoi(fmt.Sprintf("%x", data[1]))
		if numberOne < 81 || numberOne > 89 {
			data = data[2:]
		} else {
			data = data[numberOne-78:]
		}

		for {
			if len(data) == 0 {
				break
			}
			if data[0] != 0x04 {
				break
			}
			numberOne, _ = strconv.Atoi(fmt.Sprintf("%x", data[1]))
			if numberOne >= 81 && numberOne <= 89 {

				numberTwo := utils.Byte.BytesToInt(data[2 : numberOne-78])
				Value := utils.Byte.IsPrintableInfo(data[numberOne-78 : numberTwo+numberOne-78])
				if len(data) >= numberTwo+numberOne-78 {
					data = data[numberTwo+numberOne-78:]
				} else {
					return strings.TrimRight(content, "\n "), data
				}
				content += Value + "\n "
			} else {
				lengthValue, _ := strconv.ParseInt(fmt.Sprintf("%x", data[1]), 16, 64)
				Value := fmt.Sprintf("%s", data[2:lengthValue+2])
				if len(data) >= int(lengthValue)+2 {
					data = data[lengthValue+2:]
				} else {
					return strings.TrimRight(content, "\n "), data
				}
				content += Value + "\n "
			}
		}
		return strings.TrimRight(content, "\n "), data
	}

	// 解析searchResEntry数据
	searchResEntryParse := func(data []byte) (string, error) {
		var searchResEntry []byte
		var contentAll string
		var content string

		// 获取searchResEntry数据
		numberOne, _ := strconv.Atoi(fmt.Sprintf("%x", data[1]))
		if numberOne < 81 || numberOne > 89 {
			return "", fmt.Errorf("data is not searchResEntry")
		} else {
			searchResEntry = data[numberOne-75:]
		}

		// 解析出LDAP的attributes数据
		_, str := obtainObject(searchResEntry)

		// 解析出LDAP的type数据和vals
		for len(str) != 0 {
			content, str = obtainAttribute(str)
			contentAll += content + "\n"
		}
		return contentAll, nil
	}

	var res []byte
	var result string

	// 尝试TCP连接
	conn, err := proxy.WrapperTCP("tcp", addr, 5*time.Second)
	if err != nil {
		return "", err
	}
	defer conn.Close()

	// 判断LDAP服务是否开启
	_, err = conn.Write([]byte("\x30\x0c\x02\x01\x01\x60\x07\x02\x01\x03\x04\x00\x80\x00"))
	if err != nil {
		return "", err
	}
	res, err = readDataLdap(conn)
	if err != nil {
		return "", err
	}
	if !strings.Contains(fmt.Sprintf("%x", res), "070a010004000400") && !strings.Contains(fmt.Sprintf("%x", res), "616e6f6e796d6f75732062696e6420646973616c6c6f776564") {
		return "", fmt.Errorf("no ldap service")
	}

	// 读取LDAP的数据1
	_, err = conn.Write([]byte("0%\x02\x01\x02c \x04\x00\x0a\x01\x00\x0a\x01\x00\x02\x01\x00\x02\x01\x00\x01\x01\x00\x87\x0bobjectclass0\x00"))
	if err != nil {
		return "", err
	}
	res, err = readDataLdap(conn)
	if err != nil {
		return "", err
	}
	if fmt.Sprintf("%x", res) != "300c02010265070a010004000400" && !strings.Contains(fmt.Sprintf("%x", res), "746f70040f4f70656e4c444150726f6f74445345") {
		result, err = searchResEntryParse(res)
		if err != nil {
			return "", err
		}
		return result, nil
	}

	// 读取LDAP的数据2
	_, err = conn.Write([]byte("0\x82\x02\x1a\x02\x01\x03c\x82\x02\x13\x04\x00\x0a\x01\x00\x0a\x01\x00\x02\x01\x00\x02\x01\x00\x01\x01\x00\x87\x0bobjectclass0\x82\x01\xf1\x04\x1e_domainControllerFunctionality\x04\x1aconfigurationNamingContext\x04\x0bcurrentTime\x04\x14defaultNamingContext\x04\x0bdnsHostName\x04\x13domainFunctionality\x04\x0ddsServiceName\x04\x13forestFunctionality\x04\x13highestCommittedUSN\x04\x14isGlobalCatalogReady\x04\x0eisSynchronized\x04\x13ldap-get-baseobject\x04\x0fldapServiceName\x04\x0enamingContexts\x04\x17rootDomainNamingContext\x04\x13schemaNamingContext\x04\x0aserverName\x04\x11subschemaSubentry\x04\x15supportedCapabilities\x04\x10supportedControl\x04\x15supportedLDAPPolicies\x04\x14supportedLDAPVersion\x04\x17supportedSASLMechanisms\x04\x09altServer\x04\x12supportedExtension"))
	if err != nil {
		return "", err
	}

	for fmt.Sprintf("%x", res) == "300c02010265070a010004000400" || strings.Contains(fmt.Sprintf("%x", res), "746f70040f4f70656e4c444150726f6f74445345") {
		res, err = readDataLdap(conn)
		if err != nil {
			return "", err
		}
		if len(res) == 0 {
			return "", fmt.Errorf("have ldap server, but no data")
		}
	}
	result, err = searchResEntryParse(res)
	if err != nil {
		fmt.Println(err)
	}
	return result, nil
}
