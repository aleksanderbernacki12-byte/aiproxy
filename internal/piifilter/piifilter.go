package piifilter

import (
	"regexp"
	"strconv"
	"strings"
	"time"
)

const (
	RedactedSSN        = "[REDACTED_SSN]"
	RedactedIBAN       = "[REDACTED_IBAN]"
	RedactedEmail      = "[REDACTED_EMAIL]"
	RedactedCreditCard = "[REDACTED_CREDIT_CARD]"
	RedactedPhone      = "[REDACTED_PHONE]"
)

// Redactor is the extension point for local PII detectors. A future ONNX
// name/address model can implement this interface and be appended to a
// Pipeline; implementations must perform all work locally.
type Redactor interface {
	Redact(input string) (string, bool)
}

// Pipeline applies independent redactors in order. It is immutable after
// construction and safe for concurrent use when its redactors are safe.
type Pipeline struct {
	redactors []Redactor
}

// NewPipeline creates a local redaction pipeline. Nil redactors are ignored.
func NewPipeline(redactors ...Redactor) *Pipeline {
	filtered := make([]Redactor, 0, len(redactors))
	for _, redactor := range redactors {
		if redactor != nil {
			filtered = append(filtered, redactor)
		}
	}
	return &Pipeline{redactors: filtered}
}

// Redact applies every configured redactor and reports whether any changed or
// identified the input.
func (p *Pipeline) Redact(input string) (string, bool) {
	if p == nil {
		return input, false
	}
	redacted := input
	found := false
	for _, redactor := range p.redactors {
		var detected bool
		redacted, detected = redactor.Redact(redacted)
		found = found || detected
	}
	return redacted, found
}

type regexRule struct {
	pattern     *regexp.Regexp
	replacement string
	valid       func(string) bool
}

type regexRedactor struct {
	rules []regexRule
}

// NewRegexRedactor returns the built-in deterministic detector. Candidate
// credit-card, IBAN, and Swedish personal identity numbers are checksum/date
// validated to avoid masking ordinary numeric identifiers.
func NewRegexRedactor() Redactor {
	return &regexRedactor{rules: []regexRule{
		{
			pattern:     regexp.MustCompile(`(?i)\b[a-z0-9.!#$%&'*+/=?^_{}|~-]+@[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+\b`),
			replacement: RedactedEmail,
		},
		{
			pattern:     regexp.MustCompile(`(?i)\b[A-Z]{2}[0-9]{2}(?:[ ]?[A-Z0-9]){11,30}\b`),
			replacement: RedactedIBAN,
			valid:       validIBAN,
		},
		{
			pattern:     regexp.MustCompile(`\b(?:[0-9]{8}|[0-9]{6})-[0-9]{4}\b`),
			replacement: RedactedSSN,
			valid:       validSwedishSSN,
		},
		{
			pattern:     regexp.MustCompile(`\b(?:[0-9][ -]?){12,18}[0-9]\b`),
			replacement: RedactedCreditCard,
			valid:       validCardNumber,
		},
		{
			pattern:     regexp.MustCompile(`(?:(?:\+46|\b0046)(?:[ -]?\(0\))?(?:[ -]?[0-9]){7,9}|\b07[02369](?:[ -]?[0-9]){7}|\b08(?:[ -]?[0-9]){7,8})\b`),
			replacement: RedactedPhone,
			valid:       validSwedishPhone,
		},
	}}
}

func (r *regexRedactor) Redact(input string) (string, bool) {
	redacted := input
	found := false
	for _, rule := range r.rules {
		var matched bool
		redacted, matched = replaceValidated(redacted, rule)
		found = found || matched
	}
	return redacted, found
}

func replaceValidated(input string, rule regexRule) (string, bool) {
	indices := rule.pattern.FindAllStringIndex(input, -1)
	if len(indices) == 0 {
		return input, false
	}
	var result strings.Builder
	result.Grow(len(input))
	last := 0
	found := false
	for _, index := range indices {
		candidate := input[index[0]:index[1]]
		if rule.valid != nil && !rule.valid(candidate) {
			continue
		}
		result.WriteString(input[last:index[0]])
		result.WriteString(rule.replacement)
		last = index[1]
		found = true
	}
	if !found {
		return input, false
	}
	result.WriteString(input[last:])
	return result.String(), true
}

func validSwedishSSN(candidate string) bool {
	digits := strings.ReplaceAll(candidate, "-", "")
	if len(digits) != 10 && len(digits) != 12 {
		return false
	}
	dateDigits := digits[:6]
	if len(digits) == 12 {
		dateDigits = digits[:8]
	}
	layout := "060102"
	if len(dateDigits) == 8 {
		layout = "20060102"
	}
	dayOffset := 0
	dayStart := len(dateDigits) - 2
	day, err := strconv.Atoi(dateDigits[dayStart:])
	if err != nil {
		return false
	}
	if day > 60 {
		dayOffset = 60
		day -= dayOffset
		dateDigits = dateDigits[:dayStart] + strconv.Itoa(day/10) + strconv.Itoa(day%10)
	}
	if _, err := time.Parse(layout, dateDigits); err != nil {
		return false
	}
	return validLuhn(digits[len(digits)-10:])
}

func validSwedishPhone(candidate string) bool {
	number := compact(candidate, " ()-")
	switch {
	case strings.HasPrefix(number, "+46"):
		number = "0" + strings.TrimPrefix(number, "+46")
	case strings.HasPrefix(number, "0046"):
		number = "0" + strings.TrimPrefix(number, "0046")
	}
	if strings.HasPrefix(number, "00") {
		number = number[1:]
	}
	if len(number) < 9 || len(number) > 10 || number[0] != '0' || strings.Trim(number, number[:1]) == "" {
		return false
	}
	if strings.HasPrefix(number, "07") {
		return len(number) == 10 && strings.ContainsRune("02369", rune(number[2]))
	}
	return strings.HasPrefix(number, "08")
}

func validCardNumber(candidate string) bool {
	digits := compact(candidate, " -")
	if len(digits) < 13 || len(digits) > 19 || strings.Trim(digits, digits[:1]) == "" {
		return false
	}
	return validLuhn(digits)
}

func validLuhn(digits string) bool {
	sum := 0
	parity := len(digits) % 2
	for index, character := range digits {
		if character < '0' || character > '9' {
			return false
		}
		value := int(character - '0')
		if index%2 == parity {
			value *= 2
			if value > 9 {
				value -= 9
			}
		}
		sum += value
	}
	return len(digits) > 0 && sum%10 == 0
}

func validIBAN(candidate string) bool {
	iban := strings.ToUpper(compact(candidate, " "))
	if len(iban) < 15 || len(iban) > 34 {
		return false
	}
	rearranged := iban[4:] + iban[:4]
	remainder := 0
	for _, character := range rearranged {
		switch {
		case character >= '0' && character <= '9':
			remainder = (remainder*10 + int(character-'0')) % 97
		case character >= 'A' && character <= 'Z':
			value := int(character-'A') + 10
			remainder = (remainder*100 + value) % 97
		default:
			return false
		}
	}
	return remainder == 1
}

func compact(value, cutset string) string {
	return strings.Map(func(character rune) rune {
		if strings.ContainsRune(cutset, character) {
			return -1
		}
		return character
	}, value)
}

var defaultPipeline = NewPipeline(NewRegexRedactor())

// RedactPII removes supported PII locally and reports whether a validated
// match was found. It never performs network or external API calls.
func RedactPII(input string) (string, bool) {
	return defaultPipeline.Redact(input)
}
