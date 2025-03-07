//go:build !json
// +build !json

package protocols

import (
	"fmt"
	"github.com/polite007/Milkyway/pkg/neutron/commons"
	"gopkg.in/yaml.v3"
)

type InsertionOrderedStringMap struct {
	keys   []string `yaml:"-"`
	values map[string]interface{}
}

func NewEmptyInsertionOrderedStringMap(size int) *InsertionOrderedStringMap {
	return &InsertionOrderedStringMap{
		keys:   make([]string, 0, size),
		values: make(map[string]interface{}, size),
	}
}

func NewInsertionOrderedStringMap(stringMap map[string]interface{}) *InsertionOrderedStringMap {
	result := NewEmptyInsertionOrderedStringMap(len(stringMap))

	for k, v := range stringMap {
		result.Set(k, v)
	}
	return result
}

func (insertionOrderedStringMap *InsertionOrderedStringMap) Len() int {
	return len(insertionOrderedStringMap.values)
}

// UnmarshalYAML unmarshals YAML data into the map, maintaining the insertion order
func (insertionOrderedStringMap *InsertionOrderedStringMap) UnmarshalYAML(node *yaml.Node) error {
	if node.Kind != yaml.MappingNode {
		return fmt.Errorf("expected a mapping node, got %d", node.Kind)
	}
	insertionOrderedStringMap.values = make(map[string]interface{})
	for i := 0; i < len(node.Content); i += 2 {
		key := node.Content[i].Value
		value := node.Content[i+1].Value
		insertionOrderedStringMap.Set(key, value)
	}
	return nil
}

func (insertionOrderedStringMap *InsertionOrderedStringMap) ForEach(fn func(key string, data interface{})) {
	for _, key := range insertionOrderedStringMap.keys {
		fn(key, insertionOrderedStringMap.values[key])
	}
}

func (insertionOrderedStringMap *InsertionOrderedStringMap) Set(key string, value interface{}) {
	_, present := insertionOrderedStringMap.values[key]
	insertionOrderedStringMap.values[key] = value
	if !present {
		insertionOrderedStringMap.keys = append(insertionOrderedStringMap.keys, key)
	}
}

type Variable struct {
	InsertionOrderedStringMap `yaml:"-" json:"-"`
}

// Evaluate returns a finished map of variables based on set values
func (variables *Variable) Evaluate(values map[string]interface{}) map[string]interface{} {
	result := make(map[string]interface{}, variables.Len())
	variables.ForEach(func(key string, value interface{}) {
		result[key] = evaluateVariableValue(commons.ToString(value), values, result)
	})
	return result
}

func (variables *Variable) UnmarshalYAML(unmarshal func(interface{}) error) error {
	variables.InsertionOrderedStringMap = InsertionOrderedStringMap{}
	if err := unmarshal(&variables.InsertionOrderedStringMap); err != nil {
		return err
	}
	evaluated := variables.Evaluate(map[string]interface{}{})
	for k, v := range evaluated {
		variables.Set(k, v)
	}
	return nil
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
