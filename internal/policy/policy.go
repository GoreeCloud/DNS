package policy

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/miekg/dns"
)

// MaxFileBytes bounds memory consumption for a potentially untrusted rules file.
const MaxFileBytes = 16 << 20
const maxRules = 250000

// Decision describes the result of evaluating a domain against policy.
type Decision string

const (
	Unmatched Decision = "unmatched"
	Blocked   Decision = "blocked"
	Allowed   Decision = "allowed"
)

// Rules is immutable after Parse. Callers may safely share it between DNS
// queries and replace the whole instance atomically during a reload.
type Rules struct {
	deny  map[string]struct{}
	allow map[string]struct{}
}

func Empty() *Rules {
	return &Rules{deny: make(map[string]struct{}), allow: make(map[string]struct{})}
}

func (r *Rules) Count() int      { return len(r.deny) + len(r.allow) }
func (r *Rules) AllowCount() int { return len(r.allow) }

// ValidateDomain accepts ordinary ASCII DNS labels and IDNA A-labels,
// but not wildcards, URLs, IPs, domain rules, or raw resolver addresses.
func ValidateDomain(name string) (string, error) {
	name = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(name)), ".")
	if len(name) == 0 || len(name) > 253 || !strings.Contains(name, ".") ||
		strings.ContainsAny(name, "*/:\\ \t\r\n") {
		return "", fmt.Errorf("invalid domain")
	}
	if _, ok := dns.IsDomainName(name); !ok {
		return "", fmt.Errorf("invalid domain")
	}
	return name, nil
}

// Decide gives allow exceptions priority over deny rules across all suffixes.
func (r *Rules) Decide(name string) Decision {
	name = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(name)), ".")
	blocked := false
	for {
		if _, ok := r.allow[name]; ok {
			return Allowed
		}
		if _, ok := r.deny[name]; ok {
			blocked = true
		}
		idx := strings.IndexByte(name, '.')
		if idx < 0 {
			break
		}
		name = name[idx+1:]
	}
	if blocked {
		return Blocked
	}
	return Unmatched
}

func (r *Rules) Matches(name string) bool { return r.Decide(name) == Blocked }

// Parse supports:
// - plain blocked domains, including subdomains;
// - hosts-file 0.0.0.0, 127.0.0.1 and :: lines;
// - AdGuard ||domain^ blocking and @@||domain^ exceptions.
//
// Unknown syntax is rejected rather than silently skipped. All loaded policy
// is validated before being returned to a caller for atomic replacement.
func Parse(reader io.Reader) (*Rules, error) {
	content, err := io.ReadAll(io.LimitReader(reader, MaxFileBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read policy: %w", err)
	}
	if len(content) > MaxFileBytes {
		return nil, fmt.Errorf("policy exceeds %d-byte limit", MaxFileBytes)
	}
	scanner := bufio.NewScanner(bytes.NewReader(content))
	scanner.Buffer(make([]byte, 4096), 256<<10)
	result := Empty()
	lineNumber := 0
	for scanner.Scan() {
		lineNumber++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "!") {
			continue
		}
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = strings.TrimSpace(line[:i])
			if line == "" {
				continue
			}
		}
		if strings.HasPrefix(line, "@@") {
			exception := strings.TrimPrefix(line, "@@")
			if !strings.HasPrefix(exception, "||") || !strings.HasSuffix(exception, "^") {
				return nil, fmt.Errorf("policy line %d: unsupported exception syntax", lineNumber)
			}
			if err := result.add(strings.TrimSuffix(strings.TrimPrefix(exception, "||"), "^"), true); err != nil {
				return nil, fmt.Errorf("policy line %d: %w", lineNumber, err)
			}
		} else if strings.HasPrefix(line, "||") {
			if !strings.HasSuffix(line, "^") {
				return nil, fmt.Errorf("policy line %d: unsupported rule syntax", lineNumber)
			}
			if err := result.add(strings.TrimSuffix(strings.TrimPrefix(line, "||"), "^"), false); err != nil {
				return nil, fmt.Errorf("policy line %d: %w", lineNumber, err)
			}
		} else {
			fields := strings.Fields(line)
			if len(fields) >= 2 && (fields[0] == "0.0.0.0" || fields[0] == "127.0.0.1" || fields[0] == "::") {
				for _, domain := range fields[1:] {
					if err := result.add(domain, false); err != nil {
						return nil, fmt.Errorf("policy line %d: %w", lineNumber, err)
					}
				}
			} else if len(fields) == 1 {
				if err := result.add(fields[0], false); err != nil {
					return nil, fmt.Errorf("policy line %d: %w", lineNumber, err)
				}
			} else {
				return nil, fmt.Errorf("policy line %d: unsupported syntax", lineNumber)
			}
		}
		if result.Count() > maxRules {
			return nil, fmt.Errorf("policy exceeds %d-rule limit", maxRules)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read policy line %d: %w", lineNumber+1, err)
	}
	return result, nil
}

func (r *Rules) add(name string, exception bool) error {
	domain, err := ValidateDomain(name)
	if err != nil {
		return err
	}
	if exception {
		r.allow[domain] = struct{}{}
	} else {
		r.deny[domain] = struct{}{}
	}
	return nil
}

func Load(path string) (*Rules, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	return Parse(file)
}
