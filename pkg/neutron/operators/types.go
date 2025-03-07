package operators

// ExtractorType is the type of the extractor specified
type ExtractorType int

// name:ExtractorType
const (
	// name:regex
	RegexExtractor ExtractorType = iota + 1
	// name:kval
	KValExtractor
	//XPathExtractor
	JSONExtractor
	DSLExtractor

	limit
)

// extractorMappings is a table for conversion of extractor type from string.
var extractorMappings = map[string]ExtractorType{
	"regex": RegexExtractor,
	"kval":  KValExtractor,
	"dsl":   DSLExtractor,
	//"xpath": XPathExtractor,
	//"json": JSONExtractor,
}

// GetType returns the type of the matcher
func (e *Extractor) GetType() ExtractorType {
	return e.extractorType
}

// GetSupportedExtractorTypes returns list of supported types
func GetSupportedExtractorTypes() []ExtractorType {
	var result []ExtractorType
	for index := ExtractorType(1); index < limit; index++ {
		result = append(result, index)
	}
	return result
}

// MatcherType is the type of the matcher specified
type MatcherType = int

const (
	// WordsMatcher matches responses with words
	WordsMatcher MatcherType = iota + 1
	// RegexMatcher matches responses with regexes
	RegexMatcher
	// BinaryMatcher matches responses with words
	BinaryMatcher
	// StatusMatcher matches responses with status codes
	StatusMatcher
	// SizeMatcher matches responses with response size
	SizeMatcher
	// DSLMatcher matches based upon dsl syntax
	DSLMatcher
)

// matcherTypes is an table for conversion of matcher type from string.
var matcherTypes = map[string]MatcherType{
	"status": StatusMatcher,
	"size":   SizeMatcher,
	"word":   WordsMatcher,
	"regex":  RegexMatcher,
	"binary": BinaryMatcher,
	"dsl":    DSLMatcher,
}

// conditionType is the type of condition for matcher
type ConditionType int

const (
	// ANDCondition matches responses with AND condition in arguments.
	ANDCondition ConditionType = iota + 1
	// ORCondition matches responses with AND condition in arguments.
	ORCondition
)

// conditionTypes is an table for conversion of condition type from string.
var conditionTypes = map[string]ConditionType{
	"and": ANDCondition,
	"or":  ORCondition,
}
