package network

import (
	"net"
	"strings"

	"github.com/polite007/Milkyway/pkg/neutron/operators"
	protocols "github.com/polite007/Milkyway/pkg/neutron/protocols"
)

// Request contains a Network protocol request to be made from a template
type Request struct {
	ID string `json:"id" yaml:"id"`

	// Address is the address to send requests to (host:port:tls combos generally)
	Address   []string `json:"host" yaml:"host"`
	addresses []addressKV

	// AttackType is the attack type
	// Sniper, PitchFork and ClusterBomb. Default is Sniper
	AttackType string `json:"attack" yaml:"attack"`
	// Path contains the path/s for the request variables
	Payloads map[string]interface{} `json:"payloads" yaml:"payloads"`

	// Payload is the payload to send for the network request
	Inputs []*Input `json:"inputs" yaml:"inputs"`
	// ReadSize is the size of response to read (1024 if not provided by default)
	ReadSize int `json:"read-size" yaml:"read-size"`

	ReadAll bool `json:"read-all" yaml:"read-all"`

	operators.Operators `json:",inline,omitempty" yaml:",inline,omitempty"`
	// Operators for the current request go here.
	CompiledOperators *operators.Operators
	dialer            *net.Dialer
	generator         *protocols.Generator
	attackType        protocols.Type
	// cache any variables that may be needed for operation.
	//dialer  *fastdialer.Dialer
	options *protocols.ExecuterOptions
}

type addressKV struct {
	address string
	tls     bool
}

// Input is the input to send on the network
type Input struct {
	// Data is the data to send as the input
	Data string `json:"data"`
	// Type is the type of input - hex, text.
	Type string `json:"type"`
	// Read is the number of bytes to read from socket
	Read int `json:"read"`
	// Name is the optional name of the input to provide matching on
	Name string `json:"name"`
}

// GetID returns the unique ID of the request if any.
func (r *Request) GetID() string {
	return r.ID
}

// Compile compiles the protocol request for further execution.
func (r *Request) Compile(options *protocols.ExecuterOptions) error {
	var shouldUseTLS bool
	var err error
	r.options = options
	for _, address := range r.Address {
		// check if the connection should be encrypted
		if strings.HasPrefix(address, "tls://") {
			shouldUseTLS = true
			address = strings.TrimPrefix(address, "tls://")
		}
		r.addresses = append(r.addresses, addressKV{address: address, tls: shouldUseTLS})
	}
	// Pre-compile any input dsl functions before executing the request.
	for _, input := range r.Inputs {
		if input.Type != "" {
			continue
		}
	}

	if len(r.Payloads) > 0 {
		attackType := r.AttackType
		if attackType == "" {
			attackType = "sniper"
		}
		r.attackType = protocols.StringToType[attackType]

		// Resolve payload paths if they are files.
		//for name, payload := range r.Payloads {
		//	payloadStr, ok := payload.(string)
		//	if ok {
		//		final, resolveErr := options.Catalog.ResolvePath(payloadStr, options.TemplatePath)
		//		if resolveErr != nil {
		//			return err
		//		}
		//		r.Payloads[name] = final
		//	}
		//}
		r.generator, err = protocols.NewGenerator(r.Payloads, r.attackType)
		if err != nil {
			return err
		}
	}

	// Create a client for the class
	client, err := Get()
	if err != nil {
		return err
	}
	r.dialer = client

	if len(r.Matchers) > 0 || len(r.Extractors) > 0 {
		compiled := &r.Operators
		if err := compiled.Compile(); err != nil {
			return err
		}
		r.CompiledOperators = compiled
	}
	return nil
}

// Requests returns the total number of requests the YAML rule will perform
func (r *Request) Requests() int {
	return len(r.Address)
}
