package protocol_scan

import (
	"bytes"
	"encoding/hex"
	"github.com/polite007/Milkyway/common/proxy"
	"time"
)

func RdpScan(addr string) (string, error) {
	var (
		payload = "0300002a25e00000000000436f6f6b69653a206d737473686173683d6e6d61700d0a0100080003000000"
	)
	conn, err := proxy.WrapperTCP("tcp", addr, 5*time.Second)
	if err == nil {
		defer conn.Close()
		requestPayload, _ := hex.DecodeString(payload)
		_, err = conn.Write(requestPayload)
		if err != nil {
			return "", err
		}
		resp, err := ReadDataRdp(conn)
		if err != nil {
			return "", err
		}
		if len(resp) >= 12 {
			if bytes.Equal(resp[11:12], []byte{0x02}) {
				return "RDP Negotiation Response", nil
			} else {
				return "", ErrNoCurrProtocol
			}
		} else {
			return "", ErrNotEnoughSize
		}
	} else {
		return "", err
	}
}