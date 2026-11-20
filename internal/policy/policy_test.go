package policy

import (
	"strings"
	"testing"
)

func TestSupportedRules(t *testing.T) {
	rules, err := Parse(strings.NewReader("! comment\nexample.com\n0.0.0.0 tracker.example  another.example\n||ads.test^\n"))
	if err != nil {
		t.Fatal(err)
	}
	if rules.Count() != 4 {
		t.Fatalf("count = %d", rules.Count())
	}
	for _, name := range []string{"example.com.", "A.EXAMPLE.COM.", "tracker.example.", "ads.test."} {
		if !rules.Matches(name) {
			t.Fatalf("should block %q", name)
		}
	}
	for _, name := range []string{"notexample.com.", "example.com.evil.", "safe.test."} {
		if rules.Matches(name) {
			t.Fatalf("unexpected block %q", name)
		}
	}
}

func TestInvalidAndUnsupportedRules(t *testing.T) {
	for _, entry := range []string{"foo bar baz", "||broken[rule^", "example.com/abc"} {
		if _, err := Parse(strings.NewReader(entry)); err == nil {
			t.Fatalf("expected error for %q", entry)
		}
	}
}
