package policy

import (
	"bytes"
	"testing"
)

// No external blocklists or network lookups are used in these parser fuzz tests.
func FuzzPolicyFileParser(f *testing.F) {
	for _, seed := range [][]byte{
		[]byte("blocked.example\n@@||allowed.example^\n"),
		[]byte("||ads.example^\n0.0.0.0 blocked.example\n"),
		[]byte("! comment\n\n"),
		[]byte("bad\\x00record\n"),
		{},
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 64<<10 {
			t.Skip()
		}
		r, err := Parse(bytes.NewReader(data))
		if err != nil {
			return
		}
		for _, host := range []string{"blocked.example", "ads.example", "sub.allowed.example", "safe.test"} {
			_ = r.Decide(host)
		}
	})
}
