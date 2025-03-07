package protocols

import "errors"

// ProtocolType is the type of the request protocol specified
type ProtocolType int

var (
	OpsecError = errors.New("opsec!")
)

// Supported values for the ProtocolType
// name:ProtocolType
const (
	// name:dns
	NetworkProtocol ProtocolType = iota + 1
	// name:file
	FileProtocol
	// name:http
	HTTPProtocol
	InvalidProtocol
)

// ExtractorTypes is a table for conversion of extractor type from string.
var protocolMappings = map[ProtocolType]string{
	InvalidProtocol: "invalid",
	FileProtocol:    "file",
	HTTPProtocol:    "http",
	NetworkProtocol: "network",
}

func (t ProtocolType) String() string {
	return protocolMappings[t]
}
