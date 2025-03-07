package protocols

type Options struct {
	VarsPayload map[string]interface{}
	AttackType  string
	Opsec       bool
	Timeout     int
}
