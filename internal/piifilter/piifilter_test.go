package piifilter

import (
	"strings"
	"testing"
)

func TestRedactPII(t *testing.T) {
	input := `{"short_ssn":"900101-0017","long_ssn":"19900101-0017","email":"Anna.Example+legal@bolag.se","iban":"SE45 5000 0000 0583 9825 7466","card":"4111-1111-1111-1111"}`
	want := `{"short_ssn":"[REDACTED_SSN]","long_ssn":"[REDACTED_SSN]","email":"[REDACTED_EMAIL]","iban":"[REDACTED_IBAN]","card":"[REDACTED_CREDIT_CARD]"}`
	got, found := RedactPII(input)
	if !found {
		t.Fatal("found = false, want true")
	}
	if got != want {
		t.Fatalf("redacted = %q, want %q", got, want)
	}
}

func TestRedactPIILeavesInvalidCandidatesUntouched(t *testing.T) {
	input := "date 991332-1234, order 1234-5678-9012-3456, iban SE00 0000 0000 0000 0000 0000"
	got, found := RedactPII(input)
	if found {
		t.Fatalf("found = true for invalid candidates: %q", got)
	}
	if got != input {
		t.Fatalf("redacted = %q, want unchanged input", got)
	}
}

func TestPipelineSupportsAdditionalLocalRedactors(t *testing.T) {
	redactor := NewPipeline(NewRegexRedactor(), staticRedactor{})
	got, found := redactor.Redact("Kontakta alice@example.com på Storgatan 1")
	if !found {
		t.Fatal("found = false, want true")
	}
	if got != "Kontakta [REDACTED_EMAIL] på [REDACTED_ADDRESS]" {
		t.Fatalf("redacted = %q", got)
	}
}

func TestNilAndEmptyPipelines(t *testing.T) {
	for name, pipeline := range map[string]*Pipeline{"nil": nil, "empty": NewPipeline(nil)} {
		t.Run(name, func(t *testing.T) {
			got, found := pipeline.Redact("alice@example.com")
			if found || got != "alice@example.com" {
				t.Fatalf("Redact = %q, %v", got, found)
			}
		})
	}
}

type staticRedactor struct{}

func (staticRedactor) Redact(input string) (string, bool) {
	const address = "Storgatan 1"
	if !strings.Contains(input, address) {
		return input, false
	}
	return strings.ReplaceAll(input, address, "[REDACTED_ADDRESS]"), true
}
