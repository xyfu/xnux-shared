package health

import (
	"encoding/json"
	"math"
	"strings"
	"testing"
)

func f(v float64) *float64 { return &v }

func deduction(r Result, item string) (Deduction, bool) {
	for _, d := range r.Deductions {
		if d.Item == item {
			return d, true
		}
	}
	return Deduction{}, false
}

// evs builds n events of a type and severity, each in state open.
func evs(typ string, sev, n int) []Event {
	out := make([]Event, n)
	for i := range out {
		out[i] = Event{ID: typ + string(rune('a'+i)), Type: typ, Severity: sev, State: StateOpen, Subject: "s" + string(rune('a'+i))}
	}
	return out
}

func TestHealthyHostScores100(t *testing.T) {
	r := Score(Input{CPUP95: f(20), MemAvailP5: f(60), SwapInP95: f(0), IOWaitP95: f(1), LoadPerCoreP95: f(0.3),
		DiskDaysToFull: f(400), DiskUsedMax: f(40), InodeUsedMax: f(5), TempMaxP95: f(50)})
	if r.Score != 100 || r.Level != LevelHealthy || len(r.Deductions) != 0 || r.Algo != Algo || r.Top() != "" {
		t.Fatalf("got %+v", r)
	}
}

func TestEmptyInputScores100(t *testing.T) {
	// No swap, no sensors, no disks: nothing to deduct.
	if r := Score(Input{}); r.Score != 100 {
		t.Fatalf("got %+v", r)
	}
}

// Every item: the start point deducts nothing, the midpoint half, the
// full point and beyond the maximum.
func TestEveryItem(t *testing.T) {
	type tc struct {
		item      string
		set       func(*Input, float64)
		from, to  float64
		max       float64
		perUnit   bool // "N each": deduct N per count, no ramp
		booleanly bool
	}
	cases := []tc{
		{item: "open_service_failed", set: func(in *Input, v float64) { in.Events = evs("service_failed", 1, int(v)) }, max: 10, perUnit: true},
		{item: "oom_24h", set: func(in *Input, v float64) { in.OOM24h = int(v) }, from: 0, to: 5, max: 15},
		{item: "service_crashes_24h", set: func(in *Input, v float64) { in.ServiceCrashes24h = int(v) }, from: 0, to: 10, max: 10},
		{item: "segfaults_24h", set: func(in *Input, v float64) { in.Segfaults24h = int(v) }, from: 2, to: 20, max: 5},
		{item: "cpu_p95", set: func(in *Input, v float64) { in.CPUP95 = f(v) }, from: 80, to: 98, max: 10},
		{item: "mem_avail_p5", set: func(in *Input, v float64) { in.MemAvailP5 = f(v) }, from: 20, to: 5, max: 10},
		{item: "swap_in_p95", set: func(in *Input, v float64) { in.SwapInP95 = f(v) }, from: 10, to: 200, max: 8},
		{item: "iowait_p95", set: func(in *Input, v float64) { in.IOWaitP95 = f(v) }, from: 10, to: 40, max: 5},
		{item: "load_per_core_p95", set: func(in *Input, v float64) { in.LoadPerCoreP95 = f(v) }, from: 1, to: 3, max: 5},
		{item: "disk_days_to_full", set: func(in *Input, v float64) { in.DiskDaysToFull = f(v); in.DiskDaysMount = "/data" }, from: 30, to: 2, max: 15},
		{item: "disk_used_pct", set: func(in *Input, v float64) { in.DiskUsedMax = f(v); in.DiskUsedMount = "/" }, from: 80, to: 97, max: 10},
		{item: "inode_used_pct", set: func(in *Input, v float64) { in.InodeUsedMax = f(v) }, from: 80, to: 97, max: 8},
		{item: "open_p1_security", set: func(in *Input, v float64) { in.Events = evs("sudo_sensitive", 1, int(v)) }, max: 8, perUnit: true},
		{item: "open_p2_security", set: func(in *Input, v float64) { in.Events = evs("proc_tmp_exec", 2, int(v)) }, max: 3, perUnit: true},
		{item: "root_password_login", set: func(in *Input, v float64) { in.RootPasswordLogin = v > 0 }, max: 5, booleanly: true},
		{item: "open_ssh_attack", set: func(in *Input, v float64) { in.Events = evs("ssh_bruteforce", 2, int(v)) }, max: 5, booleanly: true},
		{item: "open_ssh_attack_root", set: func(in *Input, v float64) { in.Events = evs("ssh_spray", 1, int(v)) }, max: 8, booleanly: true},
		{item: "temp_p95", set: func(in *Input, v float64) { in.TempMaxP95 = f(v) }, from: 75, to: 95, max: 3},
		{item: "hung_task_24h", set: func(in *Input, v float64) { in.HungTask24h = int(v) }, from: 0, to: 5, max: 3},
	}
	for _, c := range cases {
		t.Run(c.item, func(t *testing.T) {
			at := func(v float64) float64 {
				var in Input
				c.set(&in, v)
				d, _ := deduction(Score(in), c.item)
				return d.Deduct
			}
			switch {
			case c.perUnit:
				if at(0) != 0 || at(1) != c.max {
					t.Fatalf("per unit: 0 -> %v, 1 -> %v, want 0 and %v", at(0), at(1), c.max)
				}
				// Two of them are two items, within the dimension cap.
				var in Input
				c.set(&in, 2)
				sum := 0.0
				for _, d := range Score(in).Deductions {
					sum += d.Deduct
				}
				if math.Abs(sum-math.Min(2*c.max, dimMax[dimOf(t, c.item)])) > 0.15 {
					t.Fatalf("two -> %v", sum)
				}
			case c.booleanly:
				if at(0) != 0 || at(1) != c.max {
					t.Fatalf("flag: off %v, on %v", at(0), at(1))
				}
			default:
				// Counts are whole numbers, so the midpoint is rounded.
				mid := math.Round((c.from + c.to) / 2)
				want := c.max * (mid - c.from) / (c.to - c.from)
				if got := at(c.from); got != 0 {
					t.Fatalf("at start %v deducts %v", c.from, got)
				}
				if got := at(mid); math.Abs(got-want) > 0.05 {
					t.Fatalf("at midpoint %v deducts %v, want %v", mid, got, want)
				}
				beyond := c.to + (c.to - c.from)
				if got := at(beyond); got != c.max {
					t.Fatalf("beyond %v deducts %v, want %v", beyond, got, c.max)
				}
			}
		})
	}
}

func dimOf(t *testing.T, item string) string {
	var in Input
	switch item {
	case "open_service_failed":
		in.Events = evs("service_failed", 1, 1)
	case "open_p1_security":
		in.Events = evs("sudo_sensitive", 1, 1)
	case "open_p2_security":
		in.Events = evs("proc_tmp_exec", 2, 1)
	}
	d, ok := deduction(Score(in), item)
	if !ok {
		t.Fatalf("no deduction for %s", item)
	}
	return d.Dim
}

func TestDimensionCapsScaleItemsTogether(t *testing.T) {
	// Stability: 3 failed services (30) + 5 OOM (15) + 10 crashes (10) = 55, capped at 30.
	r := Score(Input{Events: evs("service_failed", 1, 3), OOM24h: 5, ServiceCrashes24h: 10})
	sum := 0.0
	for _, d := range r.Deductions {
		sum += d.Deduct
	}
	if math.Abs(sum-30) > 0.2 || r.Score != 70 {
		t.Fatalf("sum %v score %d: %+v", sum, r.Score, r.Deductions)
	}
	for i := 1; i < len(r.Deductions); i++ {
		if r.Deductions[i].Deduct > r.Deductions[i-1].Deduct {
			t.Fatalf("largest first: %+v", r.Deductions)
		}
	}
}

func TestHardCaps(t *testing.T) {
	cases := []struct {
		name  string
		in    Input
		limit int
	}{
		{"open_p0_intrusion", Input{Events: evs("ssh_breach", 0, 1)}, 20},
		{"open_docker_api", Input{Events: evs("docker_api_access", 0, 1)}, 20},
		{"open_disk_failure", Input{Events: evs("disk_error", 1, 1)}, 40},
		{"disk_full_imminent", Input{DiskDaysToFull: f(0.5), DiskDaysMount: "/"}, 40},
		{"disk_full_imminent", Input{DiskUsedMax: f(99)}, 40},
		{"oom_memory_exhausted", Input{OOM1h: 1, MemAvailNow: f(3)}, 50},
	}
	for _, c := range cases {
		r := Score(c.in)
		if r.Score > c.limit || r.Cap == nil || r.Cap.Item != c.name || r.Top() != c.name {
			t.Errorf("%s: %+v", c.name, r)
		}
	}
	// OOM with memory back above 5% does not cap.
	if r := Score(Input{OOM1h: 1, MemAvailNow: f(30)}); r.Cap != nil {
		t.Errorf("oom with memory back: %+v", r)
	}
	// Several: the lowest wins.
	if r := Score(Input{Events: append(evs("proc_reverse_shell", 0, 1), evs("fs_readonly", 1, 1)...)}); r.Score != 20 || r.Cap.Item != "open_p0_intrusion" {
		t.Errorf("lowest cap: %+v", r)
	}
	// A cap above the score leaves it alone.
	many := append(append(evs("disk_error", 1, 1), evs("sudo_sensitive", 1, 3)...), evs("service_failed", 1, 3)...)
	r := Score(Input{Events: many, OOM24h: 5, CPUP95: f(99), MemAvailP5: f(1),
		DiskUsedMax: f(98), TempMaxP95: f(99)})
	if r.Score >= 40 || r.Cap != nil {
		t.Errorf("score under the cap: %+v", r)
	}
}

func TestLevels(t *testing.T) {
	for score, want := range map[int]string{100: LevelHealthy, 90: LevelHealthy, 89: LevelNotice, 70: LevelNotice,
		69: LevelRisk, 40: LevelRisk, 39: LevelCritical, 0: LevelCritical} {
		if got := LevelOf(score); got != want {
			t.Errorf("LevelOf(%d) = %s, want %s", score, got, want)
		}
	}
}

func TestDeterministic(t *testing.T) {
	in := Input{OOM24h: 2, CPUP95: f(91.3), DiskDaysToFull: f(3.1), DiskDaysMount: "/data", Events: evs("proc_tmp_exec", 2, 2), TempMaxP95: f(80)}
	a, _ := json.Marshal(Score(in))
	for range 100 {
		b, _ := json.Marshal(Score(in))
		if string(a) != string(b) {
			t.Fatalf("not deterministic:\n%s\n%s", a, b)
		}
	}
}

func TestDescribe(t *testing.T) {
	if got := Describe("disk_days_to_full", 3.1, "/data", "zh-CN"); got != "/data 约 3.1 天后写满" {
		t.Errorf("zh: %q", got)
	}
	if got := Describe("cpu_p95", 91, "", "en"); got != "CPU usage 91% (1-hour P95)" {
		t.Errorf("en: %q", got)
	}
	// Other languages fall back to English, as the service's do.
	if got := Describe("root_password_login", 0, "", "fr"); got != "root logged in with a password in the last 24 h" {
		t.Errorf("fr: %q", got)
	}
	for item := range phrases {
		if s := Describe(item, 1, "/", "en"); s == item {
			t.Errorf("%s has no text", item)
		}
	}
}

// Accepted items are named without a value (not "CPU usage 0%").
func TestName(t *testing.T) {
	for _, c := range []struct{ item, subject, lang, want string }{
		{"cpu_p95", "", "zh-Hans", "CPU 使用率"},
		{"disk_used_pct", "/data", "en", "/data disk usage"},
		{"disk_used_pct", "", "zh-Hans", "磁盘用量"},
		{"mem_avail_p5", "", "en", "Available memory"},
	} {
		if got := Name(c.item, c.subject, c.lang); got != c.want {
			t.Errorf("%s %q %s: %q", c.item, c.subject, c.lang, got)
		}
	}
	for item := range names {
		for _, lang := range []string{"zh-Hans", "en"} {
			if got := Name(item, "/data", lang); strings.Contains(got, "%!") || strings.ContainsAny(strings.ReplaceAll(got, "24", ""), "0123456789") {
				t.Errorf("%s (%s): %q", item, lang, got)
			}
		}
	}
}

func TestSuggestionsAreNotScored(t *testing.T) {
	r := Score(Input{AgentOutdated: true})
	if r.Score != 100 || len(r.Suggestions) != 1 {
		t.Fatalf("%+v", r)
	}
}

// Every phrase renders cleanly in both languages, with or without
// placeholders.
func TestDescribeAll(t *testing.T) {
	for item := range phrases {
		for _, lang := range []string{"zh-CN", "en"} {
			if got := Describe(item, 3, "/data", lang); strings.Contains(got, "%!") {
				t.Errorf("%s (%s): %q", item, lang, got)
			}
		}
	}
}

// v3: what resolving an event gives back, half while awaiting recovery,
// 1.5 times for a recurrence, accepted items, and counts linked to events
// (L16, L24).
func TestInterventions(t *testing.T) {
	crash := Event{ID: "e1", Type: "service_failed", Severity: 1, State: StateOpen, Subject: "nginx.service", Count24h: 3}
	in := Input{Events: []Event{crash}, ServiceCrashes24h: 3}
	r := Score(in)
	d, _ := deduction(r, "open_service_failed")
	c, _ := deduction(r, "service_crashes_24h")
	if r.Score != 87 || d.EventID != "e1" || d.State != StateOpen || d.Subject != "nginx.service" || c.EventID != "e1" {
		t.Fatalf("open: %+v", r)
	}
	// Resolving it takes out its item and its occurrences: back to 100.
	if d.Gain != 13 || c.Gain != 13 {
		t.Fatalf("gain: %+v", r.Deductions)
	}
	// Acknowledged: the score does not move, the gain is shown.
	in.Events[0].State = StateInProgress
	if r := Score(in); r.Score != 87 || r.Deductions[0].State != StateInProgress {
		t.Fatalf("in progress: %+v", r)
	}
	// Resolved by hand, still failing: half, its occurrences out.
	in = Input{Events: []Event{{ID: "e1", Type: "service_failed", Severity: 1, State: StateAwaitingRecovery, Subject: "nginx.service"}}}
	if r := Score(in); r.Score != 95 || r.Deductions[0].State != StateAwaitingRecovery {
		t.Fatalf("awaiting: %+v", r)
	}
	// Still failing: resolving it leaves half, so the gain says so (L23).
	in = Input{Events: []Event{{ID: "e1", Type: "service_failed", Severity: 1, State: StateOpen, Subject: "nginx.service",
		Count24h: 3, StillFailing: true}}, ServiceCrashes24h: 3}
	if r := Score(in); r.Score != 87 || r.Deductions[0].Gain != 8 {
		t.Fatalf("still failing: %+v", r)
	}
	// A recurrence within 7 days deducts 1.5 times.
	in = Input{Events: []Event{{ID: "e2", Type: "sudo_sensitive", Severity: 1, State: StateOpen, Recurrent: true}}}
	if r := Score(in); r.Score != 88 {
		t.Fatalf("recurrent: %+v", r)
	}
	// Accepted: listed, not deducted; caps still apply.
	in = Input{CPUP95: f(98), Accepted: []Accept{{Item: "cpu_p95"}}}
	if r := Score(in); r.Score != 100 || len(r.Accepted) != 1 || r.Accepted[0].Item != "cpu_p95" {
		t.Fatalf("accepted: %+v", r)
	}
	in = Input{DiskUsedMax: f(99.5), DiskUsedMount: "/", Accepted: []Accept{{Item: "disk_used_pct"}}}
	if r := Score(in); r.Score != 40 || r.Cap == nil {
		t.Fatalf("accepting does not lift a cap: %+v", r)
	}
	// An intrusion's cap carries its event and gain.
	in = Input{Events: evs("ssh_breach", 0, 1)}
	if r := Score(in); r.Cap == nil || r.Cap.EventID != "ssh_breacha" || r.Cap.Gain != 80 {
		t.Fatalf("cap gain: %+v", r)
	}
	// ssh_root_password_login is not a security event item any more.
	in = Input{Events: evs("ssh_root_password_login", 1, 1), RootPasswordLogin: true}
	if r := Score(in); r.Score != 95 {
		t.Fatalf("root password login: %+v", r)
	}
}
