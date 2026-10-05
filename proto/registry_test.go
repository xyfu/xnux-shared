package proto

import (
	"encoding/json"
	"strings"
	"testing"
)

// Every agent event type is registered, and every registered agent type is
// an agent event type of the schema (event lifecycle §2, decision L17).
func TestRegistry(t *testing.T) {
	var doc struct {
		Defs map[string]struct {
			Properties map[string]any `json:"properties"`
		} `json:"$defs"`
	}
	if err := json.Unmarshal(SchemaV1, &doc); err != nil {
		t.Fatal(err)
	}
	dataProps := map[string]bool{}
	for name, d := range doc.Defs {
		if strings.HasPrefix(name, "data_") {
			for k := range d.Properties {
				dataProps[k] = true
			}
		}
	}
	categories := map[string]bool{CategoryState: true, CategoryRisk: true, CategoryTransient: true,
		CategoryAction: true, CategoryFinding: true, CategoryInfo: true, CategorySignal: true}
	ends := map[string]bool{EndRecovery: true, EndMetric: true, EndQuiet24h: true, EndQuiet48h: true,
		EndManual: true, EndVersion: true, EndQuiet72h: true, EndQuiet7d: true, EndMembers: true}

	for typ := range EventTypes {
		if c, ok := Registry[typ]; !ok || c.Source != SourceAgent {
			t.Errorf("agent type %s is not registered as an agent type", typ)
		}
	}
	for typ, c := range Registry {
		if c.Source == SourceAgent {
			if _, ok := EventTypes[typ]; !ok {
				t.Errorf("%s is registered as an agent type but is not in the schema", typ)
			}
		} else if c.Source != SourceServer {
			t.Errorf("%s: source %q", typ, c.Source)
		}
		if !categories[c.Category] {
			t.Errorf("%s: category %q", typ, c.Category)
		}
		if (c.Category == CategorySignal) != (c.End == "") || (c.End != "" && !ends[c.End]) {
			t.Errorf("%s: end %q does not fit category %s", typ, c.End, c.Category)
		}
		if c.Category != CategorySignal && !severities[c.Severity] {
			t.Errorf("%s: severity %q", typ, c.Severity)
		}
		for _, f := range strings.Split(c.Object, "+") {
			switch f {
			case ObjectServer, ObjectDay, ObjectCheck, ObjectMetric:
				if c.Source == SourceAgent && (f == ObjectCheck || f == ObjectMetric) {
					t.Errorf("%s: object %q is for server types", typ, f)
				}
			default:
				// Server types may name a field of the data they make,
				// as long as agents use the same name for the same thing.
				if !dataProps[f] {
					t.Errorf("%s: object field %q is not a data field", typ, f)
				}
			}
		}
	}
}

// Programs run from random temporary directories (go test, mktemp) are one
// object from run to run; another name or place is another (thread 0020).
func TestTmpPath(t *testing.T) {
	for in, want := range map[string]string{
		"/tmp/go-build3125544911/b001/api.test":       "/tmp/go-build*/b*/api.test",
		"/tmp/go-build88442211/b123/pulse.test":       "/tmp/go-build*/b*/pulse.test",
		"/tmp/tmp.Xk3fP9aQ/payload":                   "/tmp/tmp.*/payload",
		"/var/tmp/systemd-private-0123abcd9876ef/run": "/var/tmp/systemd-private-*/run",
		"/dev/shm/.x/miner":                           "/dev/shm/.x/miner",
		"/tmp/x8f3k2":                                 "/tmp/x8f3k2", // the file name stays
		"/tmp/deadbeef-cafe/x":                        "/tmp/deadbeef-cafe/x",
		"/usr/sbin/nginx":                             "/usr/sbin/nginx",
		"/opt/app1234/bin/x":                          "/opt/app1234/bin/x", // not a temporary directory
	} {
		if got := TmpPath(in); got != want {
			t.Errorf("TmpPath(%q) = %q, want %q", in, got, want)
		}
	}
	a := ObjectOf(EventProcTmpExec, map[string]any{"exe": "/tmp/go-build1/b001/api.test", "comm": "api.test"}, "")
	b := ObjectOf(EventProcTmpExec, map[string]any{"exe": "/tmp/go-build2222/b001/api.test", "comm": "api.test"}, "")
	c := ObjectOf(EventProcTmpExec, map[string]any{"exe": "/tmp/go-build3333/b001/api.test", "comm": "api.test"}, "")
	if b != c || b != "/tmp/go-build*/b*/api.test" || a == b { // 1 digit is not random
		t.Errorf("objects: %q %q %q", a, b, c)
	}
	if o := ObjectOf(EventProcReverseShell, map[string]any{"exe": "/tmp/go-build3333/sh"}, ""); o != "/tmp/go-build3333/sh" {
		t.Errorf("reverse shell object normalized: %q", o)
	}
}

func TestObjectOf(t *testing.T) {
	long := strings.Repeat("a", 300)
	cases := []struct {
		typ  string
		data map[string]any
		day  string
		want string
	}{
		{EventServiceFailed, map[string]any{"unit": "nginx.service"}, "", "nginx.service"},
		{EventSSHBreach, map[string]any{"source": "203.0.113.7"}, "", "203.0.113.0/24"},
		{EventSSHBreach, map[string]any{"source": "203.0.113.x"}, "", "203.0.113.0/24"},
		{EventSSHBreach, map[string]any{"source": "10.1.2.x"}, "", "10.1.2.0/24"},
		{EventSSHBreach, map[string]any{"source": "2001:db8:85a3::8a2e:370:7334"}, "", "2001:db8:85a3::/48"},
		{EventSSHBreach, map[string]any{"source": "2001:db8:85a3:x::"}, "", "2001:db8:85a3::/48"},
		{EventSSHBreach, map[string]any{"source": "::ffff:198.51.100.9"}, "", "198.51.100.0/24"},
		{EventSSHBreach, map[string]any{"source": "bastion.example.com"}, "", "bastion.example.com"},
		{EventProcDeletedExe, map[string]any{"exe": "/usr/sbin/sshd (deleted)"}, "", "/usr/sbin/sshd"},
		{EventProcReverseShell, map[string]any{"exe": "/usr/bin/bash", "comm": "bash"}, "", "/usr/bin/bash"},
		{EventProcReverseShell, map[string]any{"comm": "bash", "pid": 7.0}, "", "bash"},
		{EventDiskError, map[string]any{"message": "I/O error"}, "", "unknown"},
		{EventDiskError, map[string]any{"device": "dm-0"}, "", "dm-0"},
		{EventDBPublicAccess, map[string]any{"port": 5432.0}, "", "5432"},
		{EventSudoSensitive, map[string]any{"by_user": "alice", "command": "/bin/bash"}, "", "alice\x1f/bin/bash"},
		{EventSuRoot, map[string]any{"by_user": "opc"}, "2026-10-02", "opc\x1f2026-10-02"},
		{EventSSHBruteforce, map[string]any{"source": "203.0.113.7"}, "", ""},
		{EventSSHTargeted, nil, "2026-10-02", "2026-10-02"},
		{EventCheckDown, nil, "", ""},
		{"no_such_type", map[string]any{}, "", ""},
	}
	for _, c := range cases {
		if got := ObjectOf(c.typ, c.data, c.day); got != c.want {
			t.Errorf("ObjectOf(%s, %v) = %q, want %q", c.typ, c.data, got, c.want)
		}
	}
	h := ObjectOf(EventUserCreated, map[string]any{"name": long}, "")
	if len(h) != 16 || h != ObjectOf(EventUserCreated, map[string]any{"name": long}, "") {
		t.Errorf("long object not hashed to 16 stable hex characters: %q", h)
	}
}

func TestClientCategory(t *testing.T) {
	if ClientCategory(CategoryAction) != "D" || ClientCategory(CategoryFinding) != "D" || ClientCategory(CategoryState) != "A" {
		t.Fatal("client categories")
	}
}

// One bad event costs only itself (decision L17).
func TestFilterEvents(t *testing.T) {
	good := Event{ID: "01J8ZQ5V3W7X9Y2Z4A6B8C0D1E", TS: 1, Type: EventSSHBreach, Severity: SeverityP0, Count: 1, Key: "k",
		Data: map[string]any{"source": "x", "user": "root", "method": "password", "prior_failures": 0.0}}
	long := good
	long.ID, long.Type, long.Key = "01J8ZQ5V3W7X9Y2Z4A6B8C0D1F", EventSudoSensitive, strings.Repeat("k", MaxStringLen+3)
	long.Data = map[string]any{"by_user": "a", "as_user": "root", "command": "c"}
	unknown := good
	unknown.ID, unknown.Type = "01J8ZQ5V3W7X9Y2Z4A6B8C0D1G", EventCheckDown
	p := Payload{V: 1, Seq: 1, AgentVersion: "1.0.0", MachineFP: "0123456789abcdef", Redactions: map[string]int{},
		Events: []Event{long, good, unknown}}
	if err := p.ValidateHeader(); err != nil {
		t.Fatal(err)
	}
	if p.Validate() == nil {
		t.Fatal("Validate must still reject the whole payload")
	}
	dropped := p.FilterEvents()
	if len(p.Events) != 1 || p.Events[0].ID != good.ID {
		t.Fatalf("kept %+v", p.Events)
	}
	want := []DroppedEvent{{long.ID, DropInvalid}, {unknown.ID, DropUnknownType}}
	if len(dropped) != 2 || dropped[0] != want[0] || dropped[1] != want[1] {
		t.Fatalf("dropped %+v, want %+v", dropped, want)
	}
	if err := p.Validate(); err != nil {
		t.Fatalf("filtered payload rejected: %v", err)
	}

	p.Events = []Event{unknown}
	if p.FilterEvents(); p.Events != nil {
		t.Fatalf("all dropped: events = %#v, want nil", p.Events)
	}
}

// services_failed: absent and empty mean different things (decision L19).
func TestServicesFailedEncoding(t *testing.T) {
	p := Payload{V: 1, Seq: 1, AgentVersion: "1.0.0", MachineFP: "0123456789abcdef", Redactions: map[string]int{}}
	b, _ := json.Marshal(&p)
	if strings.Contains(string(b), "services_failed") {
		t.Fatalf("nil list must be omitted: %s", b)
	}
	p.ServicesFailed = []string{}
	b, _ = json.Marshal(&p)
	if !strings.Contains(string(b), `"services_failed":[]`) {
		t.Fatalf("empty list must be sent: %s", b)
	}
	p.ServicesFailed = make([]string, MaxServicesFailed+1)
	for i := range p.ServicesFailed {
		p.ServicesFailed[i] = "u.service"
	}
	if p.ValidateHeader() == nil {
		t.Fatal("too many units accepted")
	}
}

func TestClamp(t *testing.T) {
	if got := Truncate(strings.Repeat("a", 600), MaxStringLen); len(got) != MaxStringLen || !strings.HasSuffix(got, Ellipsis) {
		t.Fatalf("len %d", len(got))
	}
	if got := Truncate(strings.Repeat("é", 300), 11); got != "éééé"+Ellipsis {
		t.Fatalf("rune boundary: %q", got)
	}
	if Truncate("short", 512) != "short" {
		t.Fatal("short string changed")
	}
	e := Event{Key: strings.Repeat("k", 515), Data: map[string]any{
		"message":  strings.Repeat("m", 300),
		"device":   strings.Repeat("d", 70),
		"command":  strings.Repeat("c", 513),
		"log_tail": []any{strings.Repeat("l", 520), "ok"},
		"pid":      1.0,
	}}
	e.Clamp()
	if len(e.Key) != 512 || len(e.Data["message"].(string)) != 256 || len(e.Data["device"].(string)) != 64 ||
		len(e.Data["command"].(string)) != 512 || len(e.Data["log_tail"].([]any)[0].(string)) != 512 || e.Data["pid"] != 1.0 {
		t.Fatalf("clamp: %+v", e)
	}
}
