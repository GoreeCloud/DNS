package policy

import (
	"bytes"
	"strings"
	"testing"
)

func TestSupportedRules(t *testing.T) {
	rules, err := Parse(strings.NewReader("! comment\nexample.com\n0.0.0.0 tracker.example another.example\n||ads.test^\n@@||good.example.com^\n"))
	if err != nil {
		t.Fatal(err)
	}
	if rules.Count() != 5 || rules.AllowCount() != 1 {
		t.Fatalf("count = %d, allowed = %d", rules.Count(), rules.AllowCount())
	}
	for _, name := range []string{"example.com.", "A.EXAMPLE.COM.", "tracker.example.", "ads.test."} {
		if rules.Decide(name) != Blocked {
			t.Fatalf("should block %q", name)
		}
	}
	for _, name := range []string{"good.example.com.", "sub.good.example.com."} {
		if rules.Decide(name) != Allowed {
			t.Fatalf("should allow exception %q", name)
		}
	}
	for _, name := range []string{"notexample.com.", "example.com.evil.", "safe.test."} {
		if rules.Decide(name) != Unmatched {
			t.Fatalf("should not match %q", name)
		}
	}
}

func TestInvalidAndUnsupportedRules(t *testing.T) {
	for _, entry := range []string{
		"foo bar baz", "||broken[rule^", "example.com/abc",
		"@@some.example", "/example/", "||domain.example",
		"@@||missing-caret.example", "192.0.2.4 redirect.example",
	} {
		if _, err := Parse(strings.NewReader(entry)); err == nil {
			t.Fatalf("expected error for %q", entry)
		}
	}
}

func TestPolicyTooLargeRejected(t *testing.T) {
	_, err := Parse(bytes.NewReader(bytes.Repeat([]byte{'#'}, MaxFileBytes+1)))
	if err == nil || !strings.Contains(err.Error(), "limit") {
		t.Fatalf("expected size limit rejection, got %v", err)
	}
}

func TestLimitAndDuplicateSemantics(t *testing.T) {
	r, err := Parse(strings.NewReader("foo.example\nfoo.example\n@@||foo.example^\n"))
	if err != nil { t.Fatal(err) }
	if r.Count() != 2 || r.Decide("foo.example.") != Allowed {
		t.Fatalf("unexpected duplicate semantics: rules=%d decision=%s", r.Count(), r.Decide("foo.example."))
	}
}

func FuzzParse(f *testing.F) {
	for _, seed := range []string{"||example.org^\n", "0.0.0.0 one.example two.example\n", "@@||allow.example^\n", "bad syntax here"} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) > 128<<10 { t.Skip() }
		rules, err := Parse(bytes.NewReader(raw))
		if err == nil && rules.Count() > maxRules {
			t.Fatal("unbounded rules accepted")
		}
	})
}
