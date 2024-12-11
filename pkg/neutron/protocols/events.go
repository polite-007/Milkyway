package protocols

import "github.com/polite007/Milkyway/pkg/neutron/operators"

// CreateEvent wraps the outputEvent with the result of the operators defined on the request
func CreateEvent(request Request, outputEvent InternalEvent) *InternalWrappedEvent {
	return CreateEventWithAdditionalOptions(request, outputEvent, nil)
}

// CreateEventWithAdditionalOptions wraps the outputEvent with the result of the operators defined on the request
// and enables extending the resulting event with additional attributes or values.
func CreateEventWithAdditionalOptions(request Request, outputEvent InternalEvent,
	addAdditionalOptions func(internalWrappedEvent *InternalWrappedEvent)) *InternalWrappedEvent {
	event := &InternalWrappedEvent{InternalEvent: outputEvent}

	// Dump response variables if ran in debug mode
	for _, compiledOperator := range request.GetCompiledOperators() {
		if compiledOperator != nil {
			result, ok := compiledOperator.Execute(outputEvent, request.Match, request.Extract)
			if ok && result != nil {
				event.OperatorsResult = result
				if addAdditionalOptions != nil {
					addAdditionalOptions(event)
				}
				event.Results = append(event.Results, request.MakeResultEvent(event)...)
			}
		}
	}
	return event
}

func CreateEventWithOperatorResults(request Request, internalEvent InternalEvent, operatorResult *operators.Result) *InternalWrappedEvent {
	event := &InternalWrappedEvent{InternalEvent: internalEvent}
	event.OperatorsResult = operatorResult
	event.Results = append(event.Results, request.MakeResultEvent(event)...)
	return event
}
