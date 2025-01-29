package protocol_vul

func ProtocolVulScan(ip string, port int, protocol string) {
	switch protocol {
	case "mysql":
		mysqlScan(ip, port)
	case "redis":
		redisScan(ip, port)
	case "ssh":
		sshScan(ip, port)
	case "vnc":
		vncScan(ip, port)
	case "smb":
		smbGhost(ip, port)
		ms17010(ip, port)
	}
}
