//go:build json
// +build json

package protocols

type Variable map[string]interface{}

func (variables Variable) Len() int {
	return len(variables)
}

// Evaluate returns a finished map of variables based on set values
func (variables *Variable) Evaluate(values map[string]interface{}) map[string]interface{} {
	result := make(map[string]interface{})
	for key, value := range *variables {
		result[key] = evaluateVariableValue(commons.ToString(value), values, result)
	}
	return result
}

// evaluateVariableValue expression and returns final value
func evaluateVariableValue(expression string, values, processing map[string]interface{}) string {
	finalMap := commons.MergeMaps(values, processing)

	result, err := commons.Evaluate(expression, finalMap)
	if err != nil {
		return expression
	}
	return result
}
