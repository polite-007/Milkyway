package protocol_scan

import (
	"encoding/hex"
	"fmt"
	"github.com/polite007/Milkyway/internal/service/pact/protocol_scan/lib"
	"github.com/polite007/Milkyway/internal/utils/proxy"
	"net"
	"strings"
	"time"
)

func SmbProtocolScan(addr string) (string, error) {
	var versionList string
	var payloadListMap = map[string]string{
		"2.0.2": "00000066fe534d424000000000000000000000000000000000000000000000000000000000000000000000000000000000000000313233343536373839303132333435362400010001000000000000003132333435363738393031323334353600000000000000000202",
		"2.1.0": "00000066fe534d424000000000000000000000000000000000000000000000000000000000000000000000000000000000000000313233343536373839303132333435362400010001000000000000003132333435363738393031323334353600000000000000001002",
		"3.0.0": "00000066fe534d424000000000000000000000000000000000000000000000000000000000000000000000000000000000000000313233343536373839303132333435362400010001000000000000003132333435363738393031323334353600000000000000000003",
		"3.0.2": "00000066fe534d424000000000000000000000000000000000000000000000000000000000000000000000000000000000000000313233343536373839303132333435362400010001000000000000003132333435363738393031323334353600000000000000000203",
		"3.1.1": "00000066fe534d424000000000000000000000000000000000000000000000000000000000000000000000000000000000000000313233343536373839303132333435362400010001000000000000003132333435363738393031323334353600000000000000001103",
		"all":   "000000b4fe534d424000000000000000000000000000000000000000000000000000000000000000000000000000000000000000313233343536373839303132333435362400050001000000000000003132333435363738393031323334353670000000020000000202100200030203110300000200060000000000020002000100000001002c00000000000200020001000100200001000000000000000000000000000000000001000000000000000000000000000000",
	}
	var versionLists = map[string]string{
		"1103": "3.1.1",
		"0203": "3.0.2",
		"0003": "3.0.0",
		"1002": "2.1.0",
		"0202": "2.0.2",
	}
	var versionListArray = []string{"2.0.2", "2.1.0", "3.0.0", "3.0.2", "3.1.1"}
	// Negotiate Protocol Request/判断是否有smb服务以及smb版本
	conn, err := proxy.WrapperTCP("tcp", addr, 5*time.Second)
	if err == nil {
		defer conn.Close()
		payloadAll, _ := hex.DecodeString(payloadListMap["all"])
		_, err = conn.Write(payloadAll)
		if err != nil {
			return "", err
		}
		_, res, err := lib.ReadDataSmb(conn)
		if err != nil {
			return "", err
		}
		if !strings.Contains(fmt.Sprintf("%x", res[5:8]), "534d42") {
			return "", fmt.Errorf("no smb service")
		}
		if len(res) < 74 {
			return string(res), nil
		}
		version := versionLists[fmt.Sprintf("%x", res[72:74])]
		if version == "" {
			return "", fmt.Errorf("smb version contain fail")
		}
		// 从低到高确认smb版本
		for _, i := range versionListArray {
			conn, err = net.DialTimeout("tcp", addr, 5*time.Second)
			if err != nil {
				return "", err
			}
			defer conn.Close()
			if version == i {
				break
			}
			payload, _ := hex.DecodeString(payloadListMap[i])
			_, err = conn.Write(payload)
			if err != nil {
				return "", err
			}
			_, res, err = lib.ReadDataSmb(conn)
			if err != nil {
				return "", err
			}
			if !strings.Contains(fmt.Sprintf("%x", res), "fe534d42") || versionLists[fmt.Sprintf("%x", res[72:74])] == "" {
				continue
			}
			versionList += " " + versionLists[fmt.Sprintf("%x", res[72:74])] + "\n"
		}
		// 返回最终版本结果
		return "NT LM 0.12 (SMBv1)\n" + versionList + " " + version, err
	} else {
		return "", err
	}
}
