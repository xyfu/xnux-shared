package sanitize

import (
	"fmt"
	"sort"
	"strings"
)

// RuleDomain hides the domains a user listed, and with hide_hostname the
// hostname's own domain (thread 0037, contract C-AG-REDACT-DOMAINS).
const RuleDomain = "domain"

const domainMarker = "[REDACTED:domain]"

// NormalizeDomain cleans one redact_domains entry: trimmed, lowercase,
// without a leading "*." or "." or a trailing ".". It must have at least
// two labels of letters, digits and "-".
func NormalizeDomain(s string) (string, error) {
	d := strings.ToLower(strings.TrimSpace(s))
	d = strings.TrimPrefix(d, "*.")
	d = strings.Trim(d, ".")
	labels := strings.Split(d, ".")
	if len(labels) < 2 {
		return "", fmt.Errorf("redact_domains: %q needs at least two labels, like example.com", s)
	}
	for _, l := range labels {
		if l == "" || strings.HasPrefix(l, "-") || strings.HasSuffix(l, "-") {
			return "", fmt.Errorf("redact_domains: %q is not a domain name", s)
		}
		for i := 0; i < len(l); i++ {
			if !isDomainChar(l[i]) {
				return "", fmt.Errorf("redact_domains: %q is not a domain name", s)
			}
		}
	}
	return d, nil
}

// HostnameDomain is the domain part of a hostname: everything after its
// first label, when that leaves at least two (web-01.example.com →
// example.com); "" otherwise, so a bare "example.com" never hides "com".
func HostnameDomain(host string) string {
	_, rest, ok := strings.Cut(strings.Trim(strings.ToLower(strings.TrimSpace(host)), "."), ".")
	if !ok || !strings.Contains(rest, ".") {
		return ""
	}
	d, err := NormalizeDomain(rest)
	if err != nil {
		return ""
	}
	return d
}

// fileExts are the labels that may follow a domain in a file name
// (example.com.conf, example.com.access.log); any other label makes it a
// longer name (example.com.cn) and no match.
var fileExts = map[string]bool{
	"conf": true, "cnf": true, "cfg": true, "ini": true, "toml": true, "yaml": true, "yml": true, "json": true, "xml": true,
	"pem": true, "key": true, "crt": true, "cert": true, "cer": true, "csr": true, "der": true, "p12": true, "pfx": true, "jks": true,
	"log": true, "access": true, "error": true, "txt": true, "err": true, "out": true,
	"bak": true, "old": true, "orig": true, "swp": true, "tmp": true, "lock": true, "pid": true, "sock": true,
	// Backups and disabled copies (thread 0037): example.com.conf.dpkg-old,
	// example.com.disabled, example.com.rpmsave.
	"disabled": true, "save": true, "dpkg-old": true, "dpkg-dist": true, "dpkg-new": true, "rpmnew": true, "rpmsave": true,
	"db": true, "sqlite": true, "gz": true, "zip": true, "tar": true, "d": true,
}

// isDomainChar: a letter, digit or "-", the characters a label is made of.
func isDomainChar(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-'
}

// domainFind finds the listed domains with their boundaries: not inside a
// longer label (notexample.com), not followed by a letter or digit
// (example.community) or by a label that is no file extension
// (example.com.cn). A dot before it is a subdomain's, which stays.
func domainFind(domains []string) func(s, lower string) [][]int {
	return func(s, lower string) [][]int {
		var out [][]int
		for _, d := range domains {
			for pos := 0; pos < len(lower); {
				j := strings.Index(lower[pos:], d)
				if j < 0 {
					break
				}
				i := pos + j
				e := i + len(d)
				pos = i + 1
				if i > 0 && isDomainChar(lower[i-1]) {
					continue
				}
				if e < len(lower) {
					c := lower[e]
					if c >= 'a' && c <= 'z' || c >= '0' && c <= '9' {
						continue
					}
					if c == '.' {
						k := e + 1
						for k < len(lower) && isDomainChar(lower[k]) {
							k++
						}
						if label := lower[e+1 : k]; label != "" && !fileExts[label] {
							continue
						}
					}
				}
				out = append(out, []int{i, e})
				pos = e
			}
		}
		if len(out) < 2 {
			return out
		}
		// Several domains: in order, the longer of two overlapping ones kept.
		sort.Slice(out, func(a, b int) bool {
			if out[a][0] != out[b][0] {
				return out[a][0] < out[b][0]
			}
			return out[a][1] > out[b][1]
		})
		kept := out[:1]
		for _, m := range out[1:] {
			if m[0] >= kept[len(kept)-1][1] {
				kept = append(kept, m)
			}
		}
		return kept
	}
}

// domainRule hides the domains, or nil without any.
func domainRule(domains []string) *rule {
	if len(domains) == 0 {
		return nil
	}
	return &rule{name: RuleDomain, lower: true, fn: constant(domainMarker), find: domainFind(domains),
		pre: func(_, lower string) bool {
			for _, d := range domains {
				if strings.Contains(lower, d) {
					return true
				}
			}
			return false
		}}
}
