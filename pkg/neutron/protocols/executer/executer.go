package executer

import (
	"github.com/polite007/Milkyway/pkg/neutron/commons"
	"github.com/polite007/Milkyway/pkg/neutron/operators"
	"github.com/polite007/Milkyway/pkg/neutron/protocols"
)

type Executer struct {
	requests []protocols.Request
	options  *protocols.ExecuterOptions
}

type Event map[string]interface{}
type WrappedEvent struct {
	InternalEvent   Event
	OperatorsResult *operators.Result
}

var _ protocols.Executer = &Executer{}

// NewExecuter creates a new request executer for list of requests
func NewExecuter(requests []protocols.Request, options *protocols.ExecuterOptions) *Executer {
	return &Executer{requests: requests, options: options}
}

// Compile compiles the execution generators preparing any requests possible.
func (e *Executer) Compile() error {
	for _, request := range e.requests {
		err := request.Compile(e.options)
		if err != nil {
			return err
		}
	}
	return nil
}

func (e *Executer) Options() *protocols.ExecuterOptions {
	return e.options
}

// Requests returns the total number of requests the rule will perform
func (e *Executer) Requests() int {
	var count int
	for _, request := range e.requests {
		count += request.Requests()
	}
	return count
}

// Execute executes the protocol group and returns true or false if results were found.
func (e *Executer) Execute(input *protocols.ScanContext) (*operators.Result, error) {
	var result *operators.Result

	previous := make(map[string]interface{})
	dynamicValues := commons.MergeMaps(make(map[string]interface{}), input.Payloads)
	for _, req := range e.requests {
		err := req.ExecuteWithResults(input, dynamicValues, previous, func(event *protocols.InternalWrappedEvent) {
			if event.OperatorsResult != nil {
				result = event.OperatorsResult
			}
		})
		if err != nil {
			return nil, err
		}
	}
	return result, nil
}
