package smtp

import (
	"testing"
)

func TestReplaceHeadersReplacesExisting(t *testing.T) {
	original := "Subject: abc\r\nFrom: me\r\nTo: you\r\n\r\nbody"
	expected := "Subject: abc\r\nFrom: not-me\r\nTo: not-you\r\n\r\nbody"
	testReplaceHeaders(t, "not-me", []string{"not-you"}, original, expected)
}

func TestReplaceHeadersAddsMissingFrom(t *testing.T) {
	original := "Subject: abc\r\nTo: you\r\n\r\nbody"
	expected := "Subject: abc\r\nTo: you\r\nFrom: me\r\n\r\nbody"
	testReplaceHeaders(t, "me", []string{"you"}, original, expected)
}

func TestReplaceHeadersAddsMissingTo(t *testing.T) {
	original := "Subject: abc\r\nFrom: me\r\n\r\nbody"
	expected := "Subject: abc\r\nFrom: me\r\nTo: you\r\n\r\nbody"
	testReplaceHeaders(t, "me", []string{"you"}, original, expected)
}

func TestReplaceHeadersAddsMissingBoth(t *testing.T) {
	original := "Subject: abc\r\n\r\nbody"
	expected := "Subject: abc\r\nFrom: me\r\nTo: you\r\n\r\nbody"
	testReplaceHeaders(t, "me", []string{"you"}, original, expected)
}

func TestReplaceHeadersSupportsMultipleRecipients(t *testing.T) {
	original := "Subject: abc\r\nFrom: me\r\n\r\nbody"
	expected := "Subject: abc\r\nFrom: me\r\nTo: a, b, c\r\n\r\nbody"
	testReplaceHeaders(t, "me", []string{"a", "b", "c"}, original, expected)
}

func testReplaceHeaders(t *testing.T, sender string, recipients []string, original string, expected string) {
	actual := replaceHeaders(original, sender, recipients)
	if actual != expected {
		t.Errorf("Expected: %v\n\nGot: %v", expected, actual)
	}
}
