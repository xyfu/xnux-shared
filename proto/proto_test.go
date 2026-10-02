package proto

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

func compileSchema(t *testing.T) *jsonschema.Schema {
	t.Helper()
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(SchemaV1))
	if err != nil {
		t.Fatalf("parse schema: %v", err)
	}
	c := jsonschema.NewCompiler()
	c.DefaultDraft(jsonschema.Draft2020)
	if err := c.AddResource("ingest.v1.schema.json", doc); err != nil {
		t.Fatalf("add schema: %v", err)
	}
	s, err := c.Compile("ingest.v1.schema.json")
	if err != nil {
		t.Fatalf("compile schema: %v", err)
	}
	return s
}

func validate(s *jsonschema.Schema, b []byte) error {
	v, err := jsonschema.UnmarshalJSON(bytes.NewReader(b))
	if err != nil {
		return err
	}
	return s.Validate(v)
}

func fixtures(t *testing.T, dir string) map[string][]byte {
	t.Helper()
	paths, err := filepath.Glob(filepath.Join("testdata", dir, "*.json"))
	if err != nil || len(paths) == 0 {
		t.Fatalf("no fixtures in testdata/%s: %v", dir, err)
	}
	out := make(map[string][]byte, len(paths))
	for _, p := range paths {
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		out[filepath.Base(p)] = b
	}
	return out
}

// Valid payloads must pass the schema, decode strictly into Payload (so the Go
// types cover every field the schema allows in the fixtures), and re-encode
// into JSON that still passes the schema and carries the same content.
func TestValidPayloadsRoundTrip(t *testing.T) {
	s := compileSchema(t)
	for name, raw := range fixtures(t, "valid") {
		t.Run(name, func(t *testing.T) {
			if err := validate(s, raw); err != nil {
				t.Fatalf("schema rejected fixture: %v", err)
			}

			dec := json.NewDecoder(bytes.NewReader(raw))
			dec.DisallowUnknownFields()
			var p Payload
			if err := dec.Decode(&p); err != nil {
				t.Fatalf("decode into Payload: %v", err)
			}

			enc, err := json.Marshal(&p)
			if err != nil {
				t.Fatal(err)
			}
			if err := validate(s, enc); err != nil {
				t.Fatalf("schema rejected Go-encoded payload: %v\n%s", err, enc)
			}

			var want, got any
			_ = json.Unmarshal(raw, &want)
			_ = json.Unmarshal(enc, &got)
			if !reflect.DeepEqual(want, got) {
				t.Fatalf("round trip changed content\nwant: %s\ngot:  %s", raw, enc)
			}
		})
	}
}

func TestInvalidPayloadsRejected(t *testing.T) {
	s := compileSchema(t)
	for name, raw := range fixtures(t, "invalid") {
		t.Run(name, func(t *testing.T) {
			if err := validate(s, raw); err == nil {
				t.Fatal("schema accepted invalid payload")
			}
		})
	}
}

// A zero-value Payload with the required header fields set must be a valid
// heartbeat; this guards the omitempty tags.
func TestHeartbeatFromGo(t *testing.T) {
	s := compileSchema(t)
	p := Payload{
		V:            SchemaVersion,
		Seq:          1,
		SentAt:       1790000000,
		AgentVersion: "1.0.0",
		MachineFP:    "0123456789abcdef",
		Redactions:   map[string]int{},
	}
	b, err := json.Marshal(&p)
	if err != nil {
		t.Fatal(err)
	}
	if err := validate(s, b); err != nil {
		t.Fatalf("heartbeat rejected: %v\n%s", err, b)
	}
}

func TestRedactionMarkers(t *testing.T) {
	var markers []struct {
		Rule string `json:"rule"`
		Re   string `json:"re"`
	}
	if err := json.Unmarshal(RedactionMarkers, &markers); err != nil {
		t.Fatal(err)
	}
	samples := map[string][]string{
		"tagged": {"password=[REDACTED:secret]"},
		"ipv4":   {"from 203.0.113.x port 22", "host vps-203-0-113-x.example.com", "static.x.113.0.x.clients.example.net"},
		"ipv6":   {"from 2001:db8:85a3:x:: port 22"},
		"email":  {"user j***@example.com"},
	}
	for _, m := range markers {
		re, err := regexp.Compile(m.Re)
		if err != nil {
			t.Fatalf("%s: %v", m.Rule, err)
		}
		ss, ok := samples[m.Rule]
		if !ok {
			t.Fatalf("no sample for marker rule %q", m.Rule)
		}
		for _, sample := range ss {
			if !re.MatchString(sample) {
				t.Errorf("%s: %q does not match %q", m.Rule, m.Re, sample)
			}
		}
	}
	if len(markers) != len(samples) {
		t.Errorf("got %d markers, want %d", len(markers), len(samples))
	}
}

// Validate is the server's hot-path check; it must agree with the schema on
// every fixture, except that JSON null decodes like an absent field and that
// the server still accepts proc_reverse_shell without exe from older agents.
func TestValidateAgreesWithSchema(t *testing.T) {
	for name, raw := range fixtures(t, "valid") {
		var p Payload
		if err := json.Unmarshal(raw, &p); err != nil {
			t.Fatal(err)
		}
		if err := p.Validate(); err != nil {
			t.Errorf("%s: valid fixture rejected: %v", name, err)
		}
	}
	for name, raw := range fixtures(t, "invalid") {
		var p Payload
		if err := json.Unmarshal(raw, &p); err != nil {
			continue // rejected at decode time
		}
		err := p.Validate()
		if name == "null_array.json" || name == "reverse_shell_no_exe.json" {
			if err != nil {
				t.Errorf("%s: the server must accept it: %v", name, err)
			}
			continue
		}
		if err == nil {
			t.Errorf("%s: invalid fixture accepted", name)
		}
	}
}

// Every event type in the schema enum has required-field rules.
func TestEventTypesMatchSchema(t *testing.T) {
	var doc struct {
		Defs map[string]struct {
			Enum []string `json:"enum"`
		} `json:"$defs"`
	}
	if err := json.Unmarshal(SchemaV1, &doc); err != nil {
		t.Fatal(err)
	}
	enum := doc.Defs["event_type"].Enum
	if len(enum) != len(EventTypes) {
		t.Fatalf("schema has %d event types, EventTypes %d", len(enum), len(EventTypes))
	}
	for _, e := range enum {
		if _, ok := EventTypes[e]; !ok {
			t.Errorf("EventTypes misses %s", e)
		}
	}
}
