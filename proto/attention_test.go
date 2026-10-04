package proto

import (
	"testing"
	"time"
)

// Every event type has a layer (specs/07 R1): a forgotten type would be
// pushed as before, silently.
func TestAttentionCoversRegistry(t *testing.T) {
	for typ, c := range Registry {
		if c.Category == CategorySignal {
			continue
		}
		if _, ok := Attention[typ]; !ok {
			t.Errorf("%s has no attention rule", typ)
		}
	}
	for typ := range Attention {
		if _, ok := Registry[typ]; !ok {
			t.Errorf("attention rule for unregistered type %s", typ)
		}
	}
}

func TestAttentionOf(t *testing.T) {
	cases := []struct {
		name string
		in   AttentionState
		want string
	}{
		{"crash within the grace", AttentionState{Type: EventServiceFailed, Severity: 1, Age: time.Minute, Failing: true}, AttentionRecord},
		{"crash recovered", AttentionState{Type: EventServiceFailed, Severity: 1, Age: 5 * time.Minute}, AttentionRecord},
		{"crash still failing", AttentionState{Type: EventServiceFailed, Severity: 1, Age: CrashGrace, Failing: true}, AttentionPush},
		{"resource short", AttentionState{Type: EventResourceThreshold, Severity: 2, Age: 10 * time.Minute}, AttentionRecord},
		{"resource lasting", AttentionState{Type: EventResourceThreshold, Severity: 2, Age: SustainedTodo}, AttentionTodo},
		{"warning line", AttentionState{Type: EventResourceThreshold, Severity: 1}, AttentionPush},
		{"swap lasting", AttentionState{Type: EventSwapThrashing, Severity: 2, Age: time.Hour}, AttentionTodo},
		{"second OOM", AttentionState{Type: EventOOMKill, Severity: 1, Recent: 2}, AttentionRecord},
		{"third OOM", AttentionState{Type: EventOOMKill, Severity: 1, Recent: 3}, AttentionTodo},
		{"certificate in 10 days", AttentionState{Type: EventSSLExpiring, Data: map[string]any{"days_left": 10}}, AttentionTodo},
		{"certificate in 2 days", AttentionState{Type: EventSSLExpiring, Data: map[string]any{"days_left": 2.0}}, AttentionPush},
		{"agent security update", AttentionState{Type: EventAgentOutdated, Data: map[string]any{"level": LevelSecurity}}, AttentionTodo},
		{"agent recommended update", AttentionState{Type: EventAgentOutdated, Data: map[string]any{"level": "recommended"}}, AttentionRecord},
		{"brute force", AttentionState{Type: EventSSHBruteforce, Severity: 1}, AttentionRecord},
		{"upgraded nginx", AttentionState{Type: EventProcDeletedExe, Data: map[string]any{"exe": "/usr/sbin/nginx (deleted)"}}, AttentionRecord},
		{"deleted /tmp binary", AttentionState{Type: EventProcDeletedExe, Data: map[string]any{"exe": "/tmp/x (deleted)"}}, AttentionPush},
		{"tmp exec", AttentionState{Type: EventProcTmpExec, Severity: 2}, AttentionPush},
		{"breach", AttentionState{Type: EventSSHBreach}, AttentionPush},
		{"exposure", AttentionState{Type: EventSSHExposure, Severity: 1}, AttentionTodo},
		{"unknown type", AttentionState{Type: "made_up"}, AttentionPush},
	}
	for _, c := range cases {
		if got := AttentionOf(c.in); got != c.want {
			t.Errorf("%s: %s, want %s", c.name, got, c.want)
		}
	}
	if !PushOnce(EventDBPublicAccess, nil) || !PushOnce(EventAgentOutdated, map[string]any{"level": LevelSecurity}) ||
		PushOnce(EventAgentOutdated, map[string]any{"level": "recommended"}) || PushOnce(EventSSHExposure, nil) {
		t.Error("push once")
	}
	if AttentionRank(AttentionPush) <= AttentionRank(AttentionTodo) || AttentionRank(AttentionTodo) <= AttentionRank(AttentionRecord) {
		t.Error("ranks")
	}
	if SystemPath("/opt/app/bin/x") || !SystemPath("/lib64/ld.so") {
		t.Error("system path")
	}
}
