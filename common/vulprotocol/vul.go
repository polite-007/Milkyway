package vulprotocol

func ProtocolVulScan(ip string, port int, protocol string) {
	switch protocol {
	case "mysql":
		MysqlScan(ip, port)
	case "redis":
		RedisScan(ip, port)
	case "ssh":
		SshScan(ip, port)
	case "vnc":
		VncScan(ip, port)
	case "smb":
		SmbGhost(ip, port)
		MS17010(ip, port)
	}
}
