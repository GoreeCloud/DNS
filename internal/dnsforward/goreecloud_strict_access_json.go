package dnsforward

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

// decodeStrictAccessSet refuses duplicate policy keys before applying a new
// access list. encoding/json otherwise silently uses the last matching key,
// which can discard earlier allow/deny rules.
const maxAccessSetBodyBytes = 1 << 20 // 1 MiB; bounds parsing work for administrative requests.

func decodeStrictAccessSet(body io.Reader) (*accessListJSON, error) {
	data, err := io.ReadAll(io.LimitReader(body, maxAccessSetBodyBytes+1))
	if err != nil {
		return nil, fmt.Errorf("reading access-list body: %w", err)
	}
	if len(data) > maxAccessSetBodyBytes {
		return nil, fmt.Errorf("access-list body exceeds 1 MiB")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	start, err := decoder.Token()
	if err != nil {
		return nil, fmt.Errorf("invalid access-list object: %w", err)
	}
	if start != json.Delim('{') {
		return nil, fmt.Errorf("access list must be a JSON object")
	}

	list := &accessListJSON{}
	seen := make([]string, 0, 3)
	for decoder.More() {
		token, err := decoder.Token()
		if err != nil {
			return nil, fmt.Errorf("invalid access-list member: %w", err)
		}
		key, ok := token.(string)
		if !ok {
			return nil, fmt.Errorf("invalid access-list member key")
		}
		for _, previous := range seen {
			if strings.EqualFold(previous, key) {
				return nil, fmt.Errorf("duplicate access-list member %q", key)
			}
		}
		seen = append(seen, key)
		switch {
		case strings.EqualFold(key, "allowed_clients"):
			err = decoder.Decode(&list.AllowedClients)
		case strings.EqualFold(key, "disallowed_clients"):
			err = decoder.Decode(&list.DisallowedClients)
		case strings.EqualFold(key, "blocked_hosts"):
			err = decoder.Decode(&list.BlockedHosts)
		default:
			return nil, fmt.Errorf("unknown access-list member %q", key)
		}
		if err != nil {
			return nil, fmt.Errorf("invalid access-list member %q: %w", key, err)
		}
	}
	end, err := decoder.Token()
	if err != nil || end != json.Delim('}') {
		return nil, fmt.Errorf("invalid access-list object ending")
	}
	var trailing json.RawMessage
	if err := decoder.Decode(&trailing); err != io.EOF {
		return nil, fmt.Errorf("unexpected trailing access-list data")
	}
	return list, nil
}
