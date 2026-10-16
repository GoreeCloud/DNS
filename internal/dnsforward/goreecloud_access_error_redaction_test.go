package dnsforward

import (
    "strings"
    "testing"
)

func TestGoreeCloudUnknownAccessKeyErrorDoesNotEchoInput(t *testing.T) {
    const marker = "confidential-field-name-do-not-echo"
    body := `{"allowed_clients":[],"disallowed_clients":[],"blocked_hosts":[], "` + marker + `": "untrusted"}`
    _, err := decodeStrictAccessSet(strings.NewReader(body))
    if err == nil {
        t.Fatal("unknown member was accepted")
    }
    if strings.Contains(err.Error(), marker) {
        t.Fatal("access-list validation error exposed untrusted member name")
    }
}
