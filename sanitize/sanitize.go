// Package sanitize is the redaction barrier: the only producer of outbound
// bytes (spec A6). Everything the agent sends, mirrors, prints in dry-run or
// writes to its log passes through a Barrier first.
//
// The guarantee is enforced by types, not review: SanitizedPayload has only
// unexported fields, so no other package can build one, and the sender,
// mirror and dry-run printer accept nothing else.
package sanitize

import (
	"bytes"
	"encoding/json"
	"fmt"
	"reflect"
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/xyfu/xnux-shared/proto"
)

// maxString bounds every string before matching (spec A6.2).
const maxString = 4 << 10

// Options configure a Barrier. Built-in rules cannot be turned off.
type Options struct {
	MaskEmail     bool
	ExtraPatterns []string
	// HideHostname, when set, replaces this hostname (and its first label)
	// with "host" in every string.
	HideHostname string
}

// Barrier applies the redaction rules. It is safe for concurrent use.
type Barrier struct {
	rules    []rule
	hostRe   *regexp.Regexp
	hostName string
}

// New compiles the rule set.
func New(o Options) (*Barrier, error) {
	custom, err := customRules(o.ExtraPatterns)
	if err != nil {
		return nil, err
	}
	b := &Barrier{rules: append(builtinRules(o.MaskEmail), custom...)}
	if h := strings.TrimSpace(o.HideHostname); h != "" && !strings.EqualFold(h, "host") {
		alts := []string{regexp.QuoteMeta(h)}
		if short, _, ok := strings.Cut(h, "."); ok && len(short) >= 3 {
			alts = append(alts, regexp.QuoteMeta(short))
		}
		b.hostRe = regexp.MustCompile(`(?i)\b(?:` + strings.Join(alts, "|") + `)\b`)
		b.hostName = h
	}
	return b, nil
}

// Stats counts replacements per rule name.
type Stats map[string]int

// String redacts a single string, e.g. a log line. Counts are discarded.
func (b *Barrier) String(s string) string {
	return b.apply(s, kindNormal, nil)
}

func (b *Barrier) apply(s string, kind fieldKind, st Stats) string {
	if len(s) > maxString {
		s = truncateUTF8(s, maxString)
	}
	if b.hostRe != nil {
		s = replace(s, b.hostRe.FindAllStringSubmatchIndex(s, -1), constant("host"), RuleHostname, st, 0)
	}
	lower, lowerOK := "", false
	for i := range b.rules {
		r := &b.rules[i]
		if r.network && kind == kindTrusted {
			continue
		}
		if r.lower && !lowerOK {
			lower, lowerOK = asciiLower(s), true
		}
		if r.pre != nil && !r.pre(s, lower) {
			continue
		}
		var noFollow byte
		if r.name == RuleIPv6 {
			noFollow = '.' // "::ffff:1.2.3.x" is an IPv4-mapped tail, already handled
		}
		if out := replace(s, r.find(s, lower), r.fn, r.name, st, noFollow); out != s {
			s, lowerOK = out, false
		}
	}
	return s
}

// asciiLower lowercases ASCII letters only, so byte offsets match s.
func asciiLower(s string) string {
	for i := 0; i < len(s); i++ {
		if c := s[i]; c >= 'A' && c <= 'Z' {
			b := []byte(s)
			for j := i; j < len(b); j++ {
				if c := b[j]; c >= 'A' && c <= 'Z' {
					b[j] = c + 'a' - 'A'
				}
			}
			return string(b)
		}
	}
	return s
}

// replace substitutes each match (submatch index slices) with fn(submatches).
// A replacement equal to the original match is not counted, which keeps
// re-sealing an already-redacted payload from inflating the counts.
func replace(s string, idx [][]int, fn func([]string) string, name string, st Stats, noFollow byte) string {
	if idx == nil {
		return s
	}
	var out strings.Builder
	last := 0
	sub := make([]string, 0, 8)
	for _, m := range idx {
		if noFollow != 0 && m[1] < len(s) && s[m[1]] == noFollow {
			continue
		}
		sub = sub[:0]
		for i := 0; i+1 < len(m); i += 2 {
			if m[i] < 0 {
				sub = append(sub, "")
			} else {
				sub = append(sub, s[m[i]:m[i+1]])
			}
		}
		repl := fn(sub)
		if repl == sub[0] {
			continue
		}
		out.WriteString(s[last:m[0]])
		out.WriteString(repl)
		last = m[1]
		if st != nil {
			st[name]++
		}
	}
	if last == 0 {
		return s
	}
	out.WriteString(s[last:])
	return out.String()
}

func truncateUTF8(s string, n int) string {
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n]
}

// SanitizedPayload is a payload that went through a Barrier. Only this
// package can create one.
type SanitizedPayload struct {
	b       []byte
	seq     uint64
	part    int
	events  int
	metrics int
}

// Bytes is the JSON body to send. Callers must not modify it.
func (p SanitizedPayload) Bytes() []byte { return p.b }
func (p SanitizedPayload) Seq() uint64   { return p.seq }
func (p SanitizedPayload) Part() int     { return p.part }
func (p SanitizedPayload) Events() int   { return p.events }
func (p SanitizedPayload) Metrics() int  { return p.metrics }
func (p SanitizedPayload) IsZero() bool  { return p.b == nil }

// Seal redacts every string in p (deeply, including event data and
// snapshots) and returns the encoded payload. p itself is not modified.
// Redaction counts are added to the payload's "redactions" field.
func (b *Barrier) Seal(p *proto.Payload) (SanitizedPayload, error) {
	cp, err := clonePayload(p)
	if err != nil {
		return SanitizedPayload{}, err
	}
	return b.sealCopy(cp)
}

// Restore re-seals payload bytes read back from the spool. The spool only
// ever holds sealed bytes, so this is a no-op re-check that keeps the type
// boundary intact: nothing reaches the sender without passing the rules.
func (b *Barrier) Restore(body []byte) (SanitizedPayload, error) {
	return b.seal(body)
}

// Split re-seals the two halves of an unsplit payload as parts 1 and 2 (used
// when the server answers 413). The second part carries no redaction counts:
// they cannot be attributed after redaction.
func (b *Barrier) Split(p SanitizedPayload) (SanitizedPayload, SanitizedPayload, error) {
	if p.part != 0 {
		return SanitizedPayload{}, SanitizedPayload{}, fmt.Errorf("sanitize: payload %d is already part %d", p.seq, p.part)
	}
	var raw proto.Payload
	if err := decode(p.b, &raw); err != nil {
		return SanitizedPayload{}, SanitizedPayload{}, err
	}
	x, y, ok := proto.Split(&raw)
	if !ok {
		return SanitizedPayload{}, SanitizedPayload{}, fmt.Errorf("sanitize: payload %d cannot be split", p.seq)
	}
	x.Part, y.Part = 1, 2
	y.Redactions = map[string]int{}
	sx, err := b.Seal(x)
	if err != nil {
		return SanitizedPayload{}, SanitizedPayload{}, err
	}
	sy, err := b.Seal(y)
	return sx, sy, err
}

func decode(body []byte, p *proto.Payload) error {
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber() // keep event data numbers exact
	if err := dec.Decode(p); err != nil {
		return fmt.Errorf("sanitize: decode payload: %w", err)
	}
	return nil
}

func (b *Barrier) seal(raw []byte) (SanitizedPayload, error) {
	var p proto.Payload
	if err := decode(raw, &p); err != nil {
		return SanitizedPayload{}, err
	}
	return b.sealCopy(&p)
}

// sealCopy redacts p in place; p must not be shared with the caller.
func (b *Barrier) sealCopy(p *proto.Payload) (SanitizedPayload, error) {
	st := Stats{}
	b.walk(reflect.ValueOf(p).Elem(), kindNormal, st)
	// Placeholders can be longer than what they replaced: cut back to the
	// schema limits so the server never rejects the payload for a length.
	for i := range p.Events {
		p.Events[i].Clamp()
	}
	for i, u := range p.ServicesFailed {
		p.ServicesFailed[i] = proto.Truncate(u, proto.MaxStringLen)
	}

	red := make(map[string]int, len(p.Redactions)+len(st))
	for k, v := range p.Redactions {
		if v > 0 {
			red[k] = v
		}
	}
	for k, v := range st {
		red[k] += v
	}
	p.Redactions = red

	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(p); err != nil {
		return SanitizedPayload{}, err
	}
	out := bytes.TrimSuffix(buf.Bytes(), []byte("\n"))
	return SanitizedPayload{b: out, seq: p.Seq, part: p.Part, events: len(p.Events), metrics: len(p.Metrics)}, nil
}

var jsonNumber = reflect.TypeFor[json.Number]()

// walk redacts every string reachable from v. Fields tagged
// `sanitize:"trusted"` skip the IP rules.
func (b *Barrier) walk(v reflect.Value, kind fieldKind, st Stats) {
	switch v.Kind() {
	case reflect.Pointer:
		if !v.IsNil() {
			b.walk(v.Elem(), kind, st)
		}
	case reflect.Struct:
		t := v.Type()
		for i := range t.NumField() {
			k := kind
			if t.Field(i).Tag.Get("sanitize") == "trusted" {
				k = kindTrusted
			}
			b.walk(v.Field(i), k, st)
		}
	case reflect.Slice, reflect.Array:
		for i := range v.Len() {
			b.walk(v.Index(i), kind, st)
		}
	case reflect.Map:
		if v.Type().Elem().Kind() == reflect.Interface {
			for _, k := range v.MapKeys() {
				v.SetMapIndex(k, reflect.ValueOf(b.any(v.MapIndex(k).Interface(), kind, st)))
			}
		}
		// Map keys are never rewritten (spec A6.2); maps of numbers hold no strings.
	case reflect.String:
		if v.Type() != jsonNumber {
			v.SetString(b.apply(v.String(), kind, st))
		}
	}
}

// any redacts decoded JSON values (event data).
func (b *Barrier) any(x any, kind fieldKind, st Stats) any {
	switch t := x.(type) {
	case string:
		return b.apply(t, kind, st)
	case map[string]any:
		for k, v := range t {
			t[k] = b.any(v, kind, st)
		}
		return t
	case []any:
		for i, v := range t {
			t[i] = b.any(v, kind, st)
		}
		return t
	default: // json.Number, bool, nil
		return x
	}
}
