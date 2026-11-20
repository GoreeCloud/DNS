package policy

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/miekg/dns"
)

// Rules is an immutable collection. A rule applies to its domain and children.
type Rules struct {
	names map[string]struct{}
}

func Empty() *Rules { return &Rules{names: make(map[string]struct{})} }

func (r *Rules) Count() int { return len(r.names) }

func (r *Rules) Matches(name string) bool {
	name = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(name)), ".")
	for {
		if _, ok := r.names[name]; ok {
			return true
		}
		idx := strings.IndexByte(name, '.')
		if idx < 0 {
			return false
		}
		name = name[idx+1:]
	}
}

// Parse supports domain lines, hosts-file entries and AdGuard ||domain^ lines.
// Exception rules and regex syntax are intentionally not interpreted.
func Parse(reader io.Reader) (*Rules, error) {
	scanner := bufio.NewScanner(io.LimitReader(reader, 16<<20+1))
	scanner.Buffer(make([]byte, 4096), 1<<20)
	result := Empty()
	lineNumber := 0
	for scanner.Scan() {
		lineNumber++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "!") ||
			strings.HasPrefix(line, "@@") {
			continue
		}
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = strings.TrimSpace(line[:i])
		}
		if strings.HasPrefix(line, "||") && strings.HasSuffix(line, "^") {
			line = strings.TrimSuffix(strings.TrimPrefix(line, "||"), "^")
		} else {
			fields := strings.Fields(line)
			if len(fields) >= 2 && (fields[0] == "0.0.0.0" || fields[0] == "127.0.0.1" || fields[0] == "::") {
				for _, name := range fields[1:] {
					if err := result.add(name); err != nil {
						return nil, fmt.Errorf("rule line %d: %w", lineNumber, err)
					}
				}
				continue
			}
			if len(fields) != 1 {
				return nil, fmt.Errorf("rule line %d: unsupported syntax", lineNumber)
			}
		}
		if err := result.add(line); err != nil {
			return nil, fmt.Errorf("rule line %d: %w", lineNumber, err)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read rules: %w", err)
	}
	return result, nil
}

func (r *Rules) add(domain string) error {
	domain = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(domain), "."))
	if len(domain) == 0 || len(domain) > 253 || strings.ContainsAny(domain, "*/:\\") {
		return fmt.Errorf("invalid domain")
	}
	if _, ok := dns.IsDomainName(domain); !ok || !strings.Contains(domain, ".") {
		return fmt.Errorf("invalid domain")
	}
	r.names[domain] = struct{}{}
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
