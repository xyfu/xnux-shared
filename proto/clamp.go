package proto

import "unicode/utf8"

// Ellipsis marks a string that was cut to fit its limit.
const Ellipsis = "…"

// dataStringLimits are the schema's byte limits of event data strings that
// are shorter than MaxStringLen.
var dataStringLimits = map[string]int{
	"message": 256,
	"cmdline": 256,
	"device":  64,
}

// Truncate cuts s to at most max bytes on a rune boundary, ending in
// Ellipsis when it had to cut; the result, ellipsis included, never
// exceeds max.
func Truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	n := max - len(Ellipsis)
	if n <= 0 {
		return s[:0]
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n] + Ellipsis
}

// Clamp cuts the event's key and data strings to the schema limits. The
// redaction barrier calls it after redacting, because a placeholder can be
// longer than what it replaced; an over-long key used to cost the whole
// payload (decision L17).
func (e *Event) Clamp() {
	e.Key = Truncate(e.Key, MaxStringLen)
	for k, v := range e.Data {
		limit := MaxStringLen
		if l, ok := dataStringLimits[k]; ok {
			limit = l
		}
		e.Data[k] = clampValue(v, limit)
	}
}

func clampValue(v any, limit int) any {
	switch t := v.(type) {
	case string:
		return Truncate(t, limit)
	case []any:
		for i, x := range t {
			t[i] = clampValue(x, limit)
		}
		return t
	case []string:
		for i, x := range t {
			t[i] = Truncate(x, limit)
		}
		return t
	case map[string]any:
		for k, x := range t {
			t[k] = clampValue(x, MaxStringLen)
		}
		return t
	default:
		return v
	}
}
