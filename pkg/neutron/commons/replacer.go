package commons

import (
	"strings"
)

const (
	markerGeneral          = "§"
	markerParenthesisOpen  = "{{"
	markerParenthesisClose = "}}"
)

// Replace replaces placeholders in template with values on the fly.
func Replace(template string, values map[string]interface{}) string {
	var replacerItems []string

	builder := &strings.Builder{}
	for key, val := range values {
		builder.WriteString(markerParenthesisOpen)
		builder.WriteString(key)
		builder.WriteString(markerParenthesisClose)
		replacerItems = append(replacerItems, builder.String())
		builder.Reset()
		replacerItems = append(replacerItems, ToString(val))

		builder.WriteString(markerGeneral)
		builder.WriteString(key)
		builder.WriteString(markerGeneral)
		replacerItems = append(replacerItems, builder.String())
		builder.Reset()
		replacerItems = append(replacerItems, ToString(val))
	}
	replacer := strings.NewReplacer(replacerItems...)
	final := replacer.Replace(template)
	return final
}

// Replace replaces one placeholder in template with one value on the fly.
func ReplaceOne(template string, key string, value interface{}) string {
	data := replaceOneWithMarkers(template, key, value, ParenthesisOpen, ParenthesisClose)
	return replaceOneWithMarkers(data, key, value, General, General)
}

// replaceOneWithMarkers is a helper function that perform one time replacement
func replaceOneWithMarkers(template, key string, value interface{}, openMarker, closeMarker string) string {
	return strings.Replace(template, openMarker+key+closeMarker, ToString(value), 1)
}

//func ReplaceRawRequest(rawrequest rawRequest, values map[string]interface{}) rawRequest {
//	rawrequest.Data = Replace(rawrequest.Data, values)
//	rawrequest.FullURL = Replace(rawrequest.FullURL, values)
//	for k, v := range rawrequest.Headers {
//		rawrequest.Headers[k] = Replace(v, values)
//	}
//	return rawrequest
//}
// MergeMaps merges two maps into a New map
