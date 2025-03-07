package templates

import (
	"errors"
	"fmt"
	"github.com/polite007/Milkyway/pkg/neutron/commons"
	"github.com/polite007/Milkyway/pkg/neutron/operators"
	"github.com/polite007/Milkyway/pkg/neutron/protocols"
	"github.com/polite007/Milkyway/pkg/neutron/protocols/executer"
	"strings"
)

func (t *Template) GetTags() []string {
	if t.Info.Tags != "" {
		return strings.Split(t.Info.Tags, ",")
	}
	return []string{}

}

func (t *Template) Compile(options *protocols.ExecuterOptions) error {
	var requests []protocols.Request
	var err error
	if options == nil {
		options = &protocols.ExecuterOptions{
			Options: &protocols.Options{
				Timeout: 5,
			},
		}
	}

	if t.Variables.Len() > 0 {
		options.Variables = t.Variables
	}

	if requestHTTP := t.GetRequests(); len(requestHTTP) > 0 {
		for _, req := range requestHTTP {
			if req.Unsafe {
				return fmt.Errorf("not impl unsafe request %s", req.Name)
			}
			requests = append(requests, req)
		}
		t.Executor = executer.NewExecuter(requests, options)
	}
	if len(t.RequestsNetwork) > 0 {
		for _, req := range t.RequestsNetwork {
			requests = append(requests, req)
		}
		t.Executor = executer.NewExecuter(requests, options)
	}

	if t.Executor != nil {
		err = t.Executor.Compile()
		if err != nil {
			return err
		}
		t.TotalRequests += t.Executor.Requests()
	} else {
		return errors.New("cannot compiled any executor")
	}
	return nil
}

func (t *Template) Execute(input string, payload map[string]interface{}) (*operators.Result, error) {
	if t.Executor.Options().Options.Opsec && t.Opsec {
		commons.Debug("(opsec!!!) skip template %s", t.Id)
		return nil, protocols.OpsecError
	}
	return t.Executor.Execute(protocols.NewScanContext(input, payload))
}
