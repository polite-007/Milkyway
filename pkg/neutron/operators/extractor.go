package operators

import (
	"fmt"
	"github.com/Knetic/govaluate"
	"github.com/polite007/Milkyway/pkg/neutron/commons"
	"regexp"
	"strings"
)

// Extractor is used to extract part of response using a regex.
type Extractor struct {
	// description: |
	//   Name of the extractor. Name should be lowercase and must not contain
	//   spaces or underscores (_).
	// examples:
	//   - value: "\"cookie-extractor\""
	Name string `json:"name,omitempty" yaml:"name,omitempty"`
	// description: |
	//   Type is the type of the extractor.
	Type string `json:"type" yaml:"type"`
	// extractorType is the internal type of the extractor
	extractorType ExtractorType

	// description: |
	//   Regex contains the regular expression patterns to extract from a part.
	//
	//   Go regex engine does not support lookaheads or lookbehinds, so as a result
	//   they are also not supported in nuclei.
	// examples:
	//   - name: Braintree Access Token Regex
	//     value: >
	//       []string{"access_token\\$production\\$[0-9a-z]{16}\\$[0-9a-f]{32}"}
	//   - name: Wordpress Author Extraction regex
	//     value: >
	//       []string{"Author:(?:[A-Za-z0-9 -\\_=\"]+)?<span(?:[A-Za-z0-9 -\\_=\"]+)?>([A-Za-z0-9]+)<\\/span>"}
	Regex []string `json:"regex,omitempty" yaml:"regex,omitempty"`
	// description: |
	//   Group specifies a numbered group to extract from the regex.
	// examples:
	//   - name: Example Regex Group
	//     value: "1"
	RegexGroup int `json:"group,omitempty" yaml:"group,omitempty"`
	// regexCompiled is the compiled variant
	regexCompiled []*regexp.Regexp

	// description: |
	//   kval contains the key-value pairs present in the HTTP response header.
	//   kval extractor can be used to extract HTTP response header and cookie key-value pairs.
	//   kval extractor inputs are case-insensitive, and does not support dash (-) in input which can replaced with underscores (_)
	// 	 For example, Content-Type should be replaced with content_type
	//
	//   A list of supported parts is available in docs for request types.
	// examples:
	//   - name: Extract Server Header From HTTP Response
	//     value: >
	//       []string{"server"}
	//   - name: Extracting value of PHPSESSID Cookie
	//     value: >
	//       []string{"phpsessid"}
	//   - name: Extracting value of Content-Type Cookie
	//     value: >
	//       []string{"content_type"}
	KVal []string `json:"kval,omitempty" yaml:"kval,omitempty"`

	// description: |
	//   JSON allows using jq-style syntax to extract items from json response
	//
	// examples:
	//   - value: >
	//       []string{".[] | .id"}
	//   - value: >
	//       []string{".batters | .batter | .[] | .id"}
	JSON []string `yaml:"json,omitempty" jsonschema:"title=json jq expressions to extract data,description=JSON JQ expressions to evaluate from response part"`
	// jsonCompiled is the compiled variant
	//jsonCompiled []*gojq.Code

	// description: |
	//   XPath allows using xpath expressions to extract items from html response
	//
	// examples:
	//   - value: >
	//       []string{"/html/body/div/p[2]/a"}
	XPath []string `json:"xpath,omitempty" yaml:"xpath,omitempty"`
	// description: |
	//   Attribute is an optional attribute to extract from response XPath.
	//
	// examples:
	//   - value: "\"href\""
	Attribute string `json:"attribute,omitempty" yaml:"attribute,omitempty" jsonschema:"title=optional attribute to extract from xpath,description=Optional attribute to extract from response XPath"`

	DSL         []string `yaml:"dsl,omitempty" json:"dsl,omitempty" `
	dslCompiled []*govaluate.EvaluableExpression
	// description: |
	//   Part is the part of the request response to extract data from.
	//
	//   Each protocol exposes a lot of different parts which are well
	//   documented in docs for each request type.
	// examples:
	//   - value: "\"body\""
	//   - value: "\"raw\""
	Part string `json:"part,omitempty" yaml:"part,omitempty"`
	// description: |
	//   Internal, when set to true will allow using the value extracted
	//   in the next request for some protocols (like HTTP).
	Internal bool `json:"internal,omitempty" yaml:"internal,omitempty"`

	// description: |
	//   CaseInsensitive enables case-insensitive extractions. Default is false.
	// values:
	//   - false
	//   - true
	CaseInsensitive bool `json:"case-insensitive,omitempty" yaml:"case-insensitive,omitempty"`
}

// CompileExtractors performs the initial setup operation on an extractor
func (e *Extractor) CompileExtractors() error {
	// Set up the extractor type
	computedType, ok := extractorMappings[e.Type]
	if !ok {
		return fmt.Errorf("unknown extractor type specified: %s", e.Type)
	}
	e.extractorType = computedType

	// Compile the regexes
	for _, regex := range e.Regex {
		compiled, err := regexp.Compile(regex)
		if err != nil {
			return fmt.Errorf("could not compile regex: %s", regex)
		}
		e.regexCompiled = append(e.regexCompiled, compiled)
	}
	for i, kval := range e.KVal {
		e.KVal[i] = strings.ToLower(kval)
	}

	//for _, query := range e.JSON {
	//	query, err := gojq.Parse(query)
	//	if err != nil {
	//		return fmt.Errorf("could not parse json: %s", query)
	//	}
	//	compiled, err := gojq.Compile(query)
	//	if err != nil {
	//		return fmt.Errorf("could not compile json: %s", query)
	//	}
	//	e.jsonCompiled = append(e.jsonCompiled, compiled)
	//}

	for _, dslExp := range e.DSL {
		compiled, err := govaluate.NewEvaluableExpressionWithFunctions(dslExp, commons.HelperFunctions)
		if err != nil {
			return fmt.Errorf("could not compile dsl expression: %s", dslExp)
		}
		e.dslCompiled = append(e.dslCompiled, compiled)
	}

	if e.CaseInsensitive {
		if e.GetType() != KValExtractor {
			return fmt.Errorf("case-insensitive flag is supported only for 'kval' extractors (not '%s')", e.Type)
		}
		for i := range e.KVal {
			e.KVal[i] = strings.ToLower(e.KVal[i])
		}
	}

	return nil
}

// ExtractRegex extracts text from a corpus and returns it
func (e *Extractor) ExtractRegex(corpus string) map[string]struct{} {
	results := make(map[string]struct{})

	groupPlusOne := e.RegexGroup + 1
	for _, regex := range e.regexCompiled {
		matches := regex.FindAllStringSubmatch(corpus, -1)

		for _, match := range matches {
			if len(match) < groupPlusOne {
				continue
			}
			matchString := match[e.RegexGroup]

			if _, ok := results[matchString]; !ok {
				results[matchString] = struct{}{}
			}
		}
	}
	return results
}

// ExtractKval extracts key value pairs from a data map
func (e *Extractor) ExtractKval(data map[string]interface{}) map[string]struct{} {
	if e.CaseInsensitive {
		inputData := data
		data = make(map[string]interface{}, len(inputData))
		for k, v := range inputData {
			if s, ok := v.(string); ok {
				v = strings.ToLower(s)
			}
			data[strings.ToLower(k)] = v
		}
	}

	results := make(map[string]struct{})
	for _, k := range e.KVal {
		item, ok := data[k]
		if !ok {
			continue
		}
		itemString := commons.ToString(item)
		if _, ok := results[itemString]; !ok {
			results[itemString] = struct{}{}
		}
	}
	return results
}

//// ExtractXPath extracts items from text using XPath selectors
//func (e *Extractor) ExtractXPath(corpus string) map[string]struct{} {
//	if strings.HasPrefix(corpus, "<?xml") {
//		return e.ExtractXML(corpus)
//	}
//	return e.ExtractHTML(corpus)
//}
//
//// ExtractHTML extracts items from HTML using XPath selectors
//func (e *Extractor) ExtractHTML(corpus string) map[string]struct{} {
//	results := make(map[string]struct{})
//
//	doc, err := htmlquery.Parse(strings.NewReader(corpus))
//	if err != nil {
//		return results
//	}
//	for _, k := range e.XPath {
//		nodes, err := htmlquery.QueryAll(doc, k)
//		if err != nil {
//			continue
//		}
//		for _, node := range nodes {
//			var value string
//
//			if e.Attribute != "" {
//				value = htmlquery.SelectAttr(node, e.Attribute)
//			} else {
//				value = htmlquery.InnerText(node)
//			}
//			if _, ok := results[value]; !ok {
//				results[value] = struct{}{}
//			}
//		}
//	}
//	return results
//}
//
//// ExtractXML extracts items from XML using XPath selectors
//func (e *Extractor) ExtractXML(corpus string) map[string]struct{} {
//	results := make(map[string]struct{})
//
//	doc, err := xmlquery.Parse(strings.NewReader(corpus))
//	if err != nil {
//		return results
//	}
//
//	for _, k := range e.XPath {
//		nodes, err := xmlquery.QueryAll(doc, k)
//		if err != nil {
//			continue
//		}
//		for _, node := range nodes {
//			var value string
//
//			if e.Attribute != "" {
//				value = node.SelectAttr(e.Attribute)
//			} else {
//				value = node.InnerText()
//			}
//			if _, ok := results[value]; !ok {
//				results[value] = struct{}{}
//			}
//		}
//	}
//	return results
//}

// ExtractJSON extracts text from a corpus using JQ queries and returns it
//func (e *Extractor) ExtractJSON(corpus string) map[string]struct{} {
//	results := make(map[string]struct{})
//
//	var jsonObj interface{}
//
//	if err := json.Unmarshal([]byte(corpus), &jsonObj); err != nil {
//		return results
//	}
//
//	for _, k := range e.jsonCompiled {
//		iter := k.Run(jsonObj)
//		for {
//			v, ok := iter.Next()
//			if !ok {
//				break
//			}
//			if _, ok := v.(error); ok {
//				break
//			}
//			var result string
//			if res, err := common.JSONScalarToString(v); err == nil {
//				result = res
//			} else if res, err := json.Marshal(v); err == nil {
//				result = string(res)
//			} else {
//				result = common.ToString(v)
//			}
//			if _, ok := results[result]; !ok {
//				results[result] = struct{}{}
//			}
//		}
//	}
//	return results
//}

// ExtractDSL execute the expression and returns the results
func (e *Extractor) ExtractDSL(data map[string]interface{}) map[string]struct{} {
	results := make(map[string]struct{})

	for _, compiledExpression := range e.dslCompiled {
		result, err := compiledExpression.Evaluate(data)
		// ignore errors that are related to missing parameters
		// eg: dns dsl can have all the parameters that are not present
		if err != nil && !strings.HasPrefix(err.Error(), "No parameter") {
			return results
		}

		if result != nil {
			resultString := fmt.Sprint(result)
			if resultString != "" {
				results[resultString] = struct{}{}
			}
		}
	}
	return results
}
