package sanitize

import (
	"fmt"
	"net/netip"
	"regexp"
	"strings"
)

// Rule names, used as keys of the payload's "redactions" counts.
const (
	RulePrivateKey = "private_key"
	RuleJWT        = "jwt"
	RuleBearer     = "bearer"
	RuleURLCred    = "url_cred"
	RuleAPIKey     = "api_key"
	RuleKVSecret   = "kv_secret"
	RuleCLISecret  = "cli_secret"
	RuleEmail      = "email"
	RuleIPv4       = "ipv4"
	RuleIPv6       = "ipv6"
	RuleCustom     = "custom"
	RuleHostname   = "hostname"
)

// fieldKind changes which rules apply to a string.
type fieldKind int

const (
	kindNormal  fieldKind = iota
	kindTrusted           // agent-generated (os, kernel, agent_version): skip IP rules
)

// rule is one redaction step. find returns match index slices in the format
// of regexp.FindAllStringSubmatchIndex; fn returns the replacement for a
// match given its submatches. Returning the match unchanged means "keep" and
// is not counted.
type rule struct {
	name    string
	find    func(s, lower string) [][]int
	fn      func(sub []string) string
	pre     func(s, lower string) bool // cheap filter: skip find when false
	network bool                       // IP rule, skipped for trusted fields
	lower   bool                       // pre or find reads the lowercased string
}

func regexFind(re *regexp.Regexp) func(s, lower string) [][]int {
	return func(s, _ string) [][]int { return re.FindAllStringSubmatchIndex(s, -1) }
}

// template returns fn expanding ${N} references like regexp.Expand.
func template(tmpl string) func(sub []string) string {
	return func(sub []string) string {
		var out []byte
		for i := 0; i < len(tmpl); i++ {
			if tmpl[i] == '$' && i+3 < len(tmpl) && tmpl[i+1] == '{' && tmpl[i+3] == '}' {
				if n := int(tmpl[i+2] - '0'); n < len(sub) {
					out = append(out, sub[n]...)
				}
				i += 3
				continue
			}
			out = append(out, tmpl[i])
		}
		return string(out)
	}
}

// keepMarked leaves a match alone when its value (submatch n) is already a
// redaction marker, so "token [REDACTED:api_key]" keeps the specific marker
// and is not counted twice.
func keepMarked(fn func([]string) string, n int) func([]string) string {
	return func(sub []string) string {
		if n < len(sub) && strings.HasPrefix(strings.TrimLeft(sub[n], `"'`), "[REDACTED:") {
			return sub[0]
		}
		return fn(sub)
	}
}

func constant(s string) func([]string) string { return func([]string) string { return s } }

func has(sub string) func(s, lower string) bool {
	return func(s, _ string) bool { return strings.Contains(s, sub) }
}

func hasLower(sub string) func(s, lower string) bool {
	return func(_, lower string) bool { return strings.Contains(lower, sub) }
}

func hasAny(subs ...string) func(s, lower string) bool {
	return func(s, _ string) bool {
		for _, x := range subs {
			if strings.Contains(s, x) {
				return true
			}
		}
		return false
	}
}

// secretKeys is the keyword alternation of spec A6.3 rule 6 (secretKeywords
// spells it out). secretStems are lowercase substrings, one of which every
// keyword contains.
const secretKeys = `password|passwd|pwd|pass|secret|token|api[_-]?key|access[_-]?key|client[_-]?secret`

var secretStems = []string{"pass", "pwd", "secret", "token", "key"}

// builtinRules are applied in order (spec A6.3). Long structures come first so
// later rules cannot cut them into pieces that escape detection.
func builtinRules(maskEmail bool) []rule {
	re := regexp.MustCompile
	rules := []rule{
		{name: RulePrivateKey, pre: has("PRIVATE KEY"), fn: constant("[REDACTED:private_key]"),
			// Spec pattern plus the PGP "PRIVATE KEY BLOCK" armor.
			find: regexFind(re(`-----BEGIN [A-Z0-9 ]*PRIVATE KEY( BLOCK)?-----[\s\S]*?(-----END [A-Z0-9 ]*PRIVATE KEY( BLOCK)?-----|$)`))},
		{name: RuleJWT, pre: has("eyJ"), fn: constant("[REDACTED:jwt]"),
			find: regexFind(re(`eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}`))},
		{name: RuleBearer, lower: true, pre: hasLower("bearer"), fn: template("${1}[REDACTED:bearer]"),
			find: regexFind(re(`(?i)(bearer\s+)[A-Za-z0-9._~+/=-]{8,}`))},
		{name: RuleURLCred, fn: template("${1}[REDACTED:cred]@"),
			pre:  func(s, _ string) bool { return strings.Contains(s, "://") && strings.Contains(s, "@") },
			find: regexFind(re(`([a-zA-Z][a-zA-Z0-9+.-]*://)[^/\s:@]+:[^/\s@]+@`))},
		{name: RuleAPIKey, fn: constant("[REDACTED:api_key]"),
			pre:  hasAny("AKIA", "ghp_", "gho_", "ghu_", "ghs_", "ghr_", "github_pat_", "sk-", "xoxb-", "xoxa-", "xoxp-", "xoxr-", "xoxs-", "AIza"),
			find: regexFind(re(`\b(AKIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{50,}|sk-[A-Za-z0-9_-]{20,}|xox[baprs]-[A-Za-z0-9-]{10,}|AIza[0-9A-Za-z_-]{35})\b`))},

		// Extension of spec A6.3 rule 6: JSON keys ("db_password": "x"), which
		// the bare-word form cannot see behind the closing quote.
		{name: RuleKVSecret, lower: true, pre: hasSecretStem, fn: keepMarked(template(`${1}"[REDACTED:secret]"`), 2),
			find: keywordFind(anchoredMatch(re(`^(?i)("(?:[A-Za-z0-9]+[_.-])*(?:`+secretKeys+`)"\s*:\s*)("(?:[^"\\]|\\.)*"|[^\s,}\]]+)`)), secretStems, true)},
		// Extension: "password <words>: value", e.g. MySQL's
		// "temporary password is generated for root@localhost: X".
		{name: RuleKVSecret, lower: true, pre: hasLower("password"), fn: keepMarked(template("${1}[REDACTED:secret]"), 2),
			find: findPasswordPhrase},
		// Spec A6.3 rule 6, extended to prefixed names such as
		// MYSQL_ROOT_PASSWORD or spring.datasource.password.
		{name: RuleKVSecret, lower: true, pre: hasSecretStem, fn: keepMarked(template("${1}${2}[REDACTED:secret]"), 3),
			find: keywordFind(matchKV, secretStems, false)},

		{name: RuleCLISecret, pre: has("-"), fn: keepMarked(template("${1}[REDACTED:secret]"), 3),
			find: regexFind(re(`(?i)(--?(password|passwd|pass|token|secret|api-key)[= ])(\S+)`))},
		// Spec limits "-pXXXX" to command lines; it is applied to every
		// string so commands quoted in logs (sudo COMMAND=...) are covered too.
		{name: RuleCLISecret, pre: hasSpaceDashP, fn: keepMarked(template("${1}[REDACTED:secret]"), 2),
			find: regexFind(re(`(\s-p)(\S{4,})`))},
	}
	if maskEmail {
		rules = append(rules, rule{name: RuleEmail, pre: has("@"), fn: template("${1}***@${2}"),
			find: regexFind(re(`\b([A-Za-z0-9._%+-])[A-Za-z0-9._%+-]*@([A-Za-z0-9.-]+\.[A-Za-z]{2,})\b`))})
	}
	return append(rules,
		rule{name: RuleIPv4, pre: has("."), find: findIPv4, fn: maskIPv4, network: true},
		rule{name: RuleIPv4, pre: has("-"), find: findIPv4Dashed, fn: maskIPv4, network: true},
		rule{name: RuleIPv6, pre: func(s, _ string) bool { return strings.Count(s, ":") >= 2 },
			find: findIPv6, fn: maskIPv6, network: true},
	)
}

func hasSecretStem(_, lower string) bool {
	for _, k := range secretStems {
		if strings.Contains(lower, k) {
			return true
		}
	}
	return false
}

func hasSpaceDashP(s, _ string) bool {
	for i := strings.Index(s, "-p"); i >= 0; {
		if i > 0 && isSpace(s[i-1]) {
			return true
		}
		j := strings.Index(s[i+2:], "-p")
		if j < 0 {
			break
		}
		i += 2 + j
	}
	return false
}

func customRules(patterns []string) ([]rule, error) {
	out := make([]rule, 0, len(patterns))
	for _, p := range patterns {
		re, err := regexp.Compile(p)
		if err != nil {
			return nil, fmt.Errorf("sanitize: custom pattern %q: %w", p, err)
		}
		out = append(out, rule{name: RuleCustom, find: regexFind(re), fn: constant("[REDACTED:custom]")})
	}
	return out, nil
}

// keywordFind runs match only where a keyword occurs, instead of letting the
// regex engine try every position of the string. For each keyword occurrence
// it tries the start of the identifier around it (so prefixed names like
// FOO_PASSWORD match) and each later start after a '.' or '-', which is where
// an unanchored \b-led pattern could also begin. With quoted, match is tried
// one byte earlier, at the opening quote. match returns submatch indexes for
// a match starting exactly at the given position, or nil.
func keywordFind(match func(s, lower string, at int) []int, keywords []string, quoted bool) func(s, lower string) [][]int {
	return func(s, lower string) [][]int {
		var out [][]int
		// next[k] caches the next occurrence of keyword k at or after pos.
		var nextBuf [8]int
		next := nextBuf[:0]
		for range keywords {
			next = append(next, -2)
		}
		pos := 0
		for pos < len(s) {
			i := -1
			for n, k := range keywords {
				if next[n] == -2 || (next[n] >= 0 && next[n] < pos) {
					next[n] = -1
					if j := strings.Index(lower[pos:], k); j >= 0 {
						next[n] = pos + j
					}
				}
				if next[n] >= 0 && (i < 0 || next[n] < i) {
					i = next[n]
				}
			}
			if i < 0 {
				break
			}
			start := i
			for start > pos && isIdent(s[start-1]) {
				start--
			}
			resume := i + 1
			for p := start; p <= i; p++ {
				if p != start && s[p-1] != '.' && s[p-1] != '-' {
					continue
				}
				at := p
				if quoted {
					if p == 0 || s[p-1] != '"' || p-1 < pos {
						continue
					}
					at = p - 1
				}
				if m := match(s, lower, at); m != nil {
					out = append(out, m)
					resume = max(resume, m[1])
					break
				}
			}
			pos = resume
		}
		return out
	}
}

// anchoredMatch adapts a regex that starts with ^ to keywordFind.
func anchoredMatch(re *regexp.Regexp) func(s, lower string, at int) []int {
	return func(s, _ string, at int) []int {
		m := re.FindStringSubmatchIndex(s[at:])
		for k := range m {
			if m[k] >= 0 {
				m[k] += at
			}
		}
		return m
	}
}

var secretKeywords = []string{"password", "passwd", "pwd", "pass", "secret", "token",
	"apikey", "api_key", "api-key", "accesskey", "access_key", "access-key",
	"clientsecret", "client_secret", "client-secret"}

// matchKV matches, at position at, the spec A6.3 rule 6 pattern extended to
// prefixed names:
//
//	(?i)\b((?:[A-Za-z0-9]+[_.-])*(?:KEYS))\b(\s*[=:]\s*|\s+)("[^"]*"|'[^']*'|[^\s,;&]+)
//
// Because the separator cannot start with an identifier character, the
// keyword must end exactly where the identifier starting at at ends.
func matchKV(s, lower string, at int) []int {
	if at > 0 && isWord(s[at-1]) || at >= len(s) || !isWord(s[at]) {
		return nil
	}
	q := at
	for q < len(s) && isIdent(s[q]) {
		q++
	}
	name := lower[at:q]
	ok := false
	for _, k := range secretKeywords {
		if strings.HasSuffix(name, k) && validPrefix(name[:len(name)-len(k)]) {
			ok = true
			break
		}
	}
	if !ok {
		return nil
	}
	// Separator, first alternative: \s*[=:]\s*
	f := q
	for f < len(s) && isSpace(s[f]) {
		f++
	}
	if f < len(s) && (s[f] == '=' || s[f] == ':') {
		g := f + 1
		for g < len(s) && isSpace(s[g]) {
			g++
		}
		if e := matchKVValue(s, g); e > g {
			return []int{at, e, at, q, q, g, g, e}
		}
	}
	// Second alternative: \s+
	if f > q {
		if e := matchKVValue(s, f); e > f {
			return []int{at, e, at, q, q, f, f, e}
		}
	}
	return nil
}

// validPrefix reports whether p matches ([a-z0-9]+[_.-])*.
func validPrefix(p string) bool {
	seg := 0
	for i := 0; i < len(p); i++ {
		c := p[i]
		switch {
		case c >= 'a' && c <= 'z' || c >= '0' && c <= '9':
			seg++
		case (c == '_' || c == '.' || c == '-') && seg > 0:
			seg = 0
		default:
			return false
		}
	}
	return seg == 0
}

// matchKVValue matches "[^"]*"|'[^']*'|[^\s,;&]+ at i and returns its end,
// or i when nothing matches.
func matchKVValue(s string, i int) int {
	if i >= len(s) {
		return i
	}
	if c := s[i]; c == '"' || c == '\'' {
		if j := strings.IndexByte(s[i+1:], c); j >= 0 {
			return i + 1 + j + 1
		}
	}
	e := i
	for e < len(s) && !isSpace(s[e]) && s[e] != ',' && s[e] != ';' && s[e] != '&' {
		e++
	}
	return e
}

func isIdent(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '.' || c == '-'
}

func isWord(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_'
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }

func isHex(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F'
}

func isSpace(c byte) bool {
	return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f' // RE2 \s
}

// findIPv4 matches \b(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\b by hand.
func findIPv4(s, _ string) [][]int { return findQuad(s, '.') }

// findIPv4Dashed finds the "1-2-3-4" form hostnames carry
// (ec2-1-2-3-4.compute-1.amazonaws.com, vps-1-2-3-4.example.com); a longer
// run of dashed numbers (a date and time) is not an address.
func findIPv4Dashed(s, _ string) [][]int { return findQuad(s, '-') }

// findQuad finds four 1-3 digit groups joined by sep, not glued to a word.
// Submatches 1-4 are the groups; submatch 5 is the whole match when it is
// part of a DNS name ("static.4.3.2.1.clients.example.net"), where the
// address may be written in reverse.
func findQuad(s string, sep byte) [][]int {
	var out [][]int
	for i := 0; i < len(s); i++ {
		if !isDigit(s[i]) || (i > 0 && isWord(s[i-1])) {
			continue
		}
		if sep == '-' && numericBefore(s, i) {
			continue
		}
		var m [12]int
		m[0], m[10], m[11] = i, -1, -1
		p, ok := i, true
		for oct := range 4 {
			q := p
			for q < len(s) && isDigit(s[q]) && q-p < 4 {
				q++
			}
			if n := q - p; n == 0 || n > 3 {
				ok = false
				break
			}
			m[2+2*oct], m[3+2*oct] = p, q
			if oct < 3 {
				if q >= len(s) || s[q] != sep {
					ok = false
					break
				}
				p = q + 1
			} else {
				if q < len(s) && (isWord(s[q]) || sep == '-' && s[q] == '-' && q+1 < len(s) && isDigit(s[q+1])) {
					ok = false
					break
				}
				p = q
			}
		}
		if ok {
			m[1] = p
			if sep == '.' && ((p+1 < len(s) && s[p] == '.' && isLetter(s[p+1])) || (i >= 2 && s[i-1] == '.' && isLetter(s[i-2]))) {
				m[10], m[11] = i, p
			}
			out = append(out, m[:])
			i = p - 1
		}
	}
	return out
}

// numericBefore reports whether s[i] follows "-" after a group of digits
// that is not the tail of a word: "2026-09-28-10-30" is one run of numbers,
// while "ec2-54-12-34-56" starts one after the word "ec2".
func numericBefore(s string, i int) bool {
	if i < 2 || s[i-1] != '-' || !isDigit(s[i-2]) {
		return false
	}
	j := i - 2
	for j > 0 && isDigit(s[j-1]) {
		j--
	}
	return j == 0 || !isWord(s[j-1])
}

func isLetter(c byte) bool { return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' }

// findIPv6 mirrors [0-9A-Fa-f:]{2,39}(%\w+)? (leftmost, greedy), keeping only
// candidates with at least two colons that are not glued to a word, so
// "std::string" is not taken for an address.
func findIPv6(s, _ string) [][]int {
	var out [][]int
	for i := 0; i < len(s); {
		if !isHex(s[i]) && s[i] != ':' {
			i++
			continue
		}
		j, colons := i, 0
		for j < len(s) && j-i < 39 && (isHex(s[j]) || s[j] == ':') {
			if s[j] == ':' {
				colons++
			}
			j++
		}
		if j-i < 2 {
			i = j
			continue
		}
		end := j
		if end+1 < len(s) && s[end] == '%' && isWord(s[end+1]) {
			end++
			for end < len(s) && isWord(s[end]) {
				end++
			}
		}
		glued := (i > 0 && isWord(s[i-1])) || (end < len(s) && isWord(s[end]))
		// An address has "::" or all 8 groups; this drops times like 10:01:02
		// before the more expensive parse.
		plausible := colons >= 7 || (colons >= 2 && strings.Contains(s[i:j], "::"))
		if plausible && !glued {
			out = append(out, []int{i, end})
		}
		i = end
	}
	return out
}

// Addresses in these ranges are kept: they help debugging and do not reveal
// a public identity.
var privatePrefixes = func() []netip.Prefix {
	var out []netip.Prefix
	for _, s := range []string{
		"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12",
		"192.0.0.0/24", "192.0.2.0/24", "192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24",
		"203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4",
		"::/128", "::1/128", "fc00::/7", "fe80::/10", "ff00::/8", "2001:db8::/32",
	} {
		out = append(out, netip.MustParsePrefix(s))
	}
	return out
}()

func isPrivate(a netip.Addr) bool {
	a = a.WithZone("")
	for _, p := range privatePrefixes {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

func maskIPv4(sub []string) string {
	sep := string(sub[0][len(sub[1])])
	a, err := netip.ParseAddr(sub[1] + "." + sub[2] + "." + sub[3] + "." + sub[4])
	if err != nil || !a.Is4() {
		return sub[0]
	}
	if len(sub) > 5 && sub[5] != "" {
		// Inside a DNS name the order is unknown (reverse DNS names write it
		// backwards): unless both readings are private, mask both ends.
		r, err := netip.ParseAddr(sub[4] + "." + sub[3] + "." + sub[2] + "." + sub[1])
		if err == nil && isPrivate(a) && isPrivate(r) {
			return sub[0]
		}
		return "x" + sep + sub[2] + sep + sub[3] + sep + "x"
	}
	if isPrivate(a) {
		return sub[0]
	}
	return sub[1] + sep + sub[2] + sep + sub[3] + sep + "x"
}

// globalUnicast is 2000::/3, where every publicly routed IPv6 address lives.
// Masking only these avoids rewriting hex-and-colon text such as "ab::cd"
// that merely parses as an address.
var globalUnicast = netip.MustParsePrefix("2000::/3")

func maskIPv6(sub []string) string {
	s := sub[0]
	a, err := netip.ParseAddr(s)
	if err != nil || !a.Is6() || a.Is4In6() || isPrivate(a) || !globalUnicast.Contains(a.WithZone("")) {
		return s
	}
	b := a.As16()
	return fmt.Sprintf("%x:%x:%x:x::", uint16(b[0])<<8|uint16(b[1]), uint16(b[2])<<8|uint16(b[3]), uint16(b[4])<<8|uint16(b[5]))
}

// findPasswordPhrase matches (?i)(\bpassword\b[^\n:="']{0,80}?:\s+)(\S+) by hand:
// the lazy {0,80} makes the regex engine backtrack at every candidate length.
func findPasswordPhrase(s, lower string) [][]int {
	var out [][]int
	for pos := 0; pos < len(s); {
		j := strings.Index(lower[pos:], "password")
		if j < 0 {
			break
		}
		i := pos + j
		pos = i + 1
		end := i + len("password")
		if (i > 0 && isWord(s[i-1])) || (end < len(s) && isWord(s[end])) {
			continue
		}
		k := end
		for k < len(s) && k-end <= 80 && s[k] != ':' && s[k] != '\n' && s[k] != '=' && s[k] != '"' && s[k] != '\'' {
			k++
		}
		if k >= len(s) || s[k] != ':' || k-end > 80 {
			continue
		}
		v := k + 1
		for v < len(s) && isSpace(s[v]) {
			v++
		}
		if v == k+1 || v >= len(s) || isSpace(s[v]) {
			continue
		}
		e := v
		for e < len(s) && !isSpace(s[e]) {
			e++
		}
		out = append(out, []int{i, e, i, v, v, e})
		pos = e
	}
	return out
}
