package dnsforward

import (
	"strings"
	"testing"
)

func TestGoreeCloudStrictAccessListJSON(t *testing.T) {
	for _, tc := range []struct {
		name    string
		payload string
		valid   bool
	}{
		{name: "single object", payload: `{"allowed_clients":["192.0.2.1"]}`, valid: true},
		{name: "whitespace after object", payload: `{"blocked_hosts":[]}  
 `, valid: true},
		{name: "second object", payload: `{"blocked_hosts":[]} {}`, valid: false},
		{name: "extra null", payload: `{"blocked_hosts":[]} null`, valid: false},
		{name: "trailing garbage", payload: `{"blocked_hosts":[]} nonsense`, valid: false},
		{name: "empty body", payload: ``, valid: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			result, err := decodeAccessSet(strings.NewReader(tc.payload))
			if (err == nil) != tc.valid {
				t.Fatalf("unexpected parse result: valid=%v err=%v", tc.valid, err)
			}
			if tc.valid && result == nil {
				t.Fatal("valid request returned a nil access-list pointer")
			}
		})
	}
}
