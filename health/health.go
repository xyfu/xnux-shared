// Package health scores a server 0–100 from what it reported (spec v1.1
// delta 8). The score starts at 100, loses points per dimension, and
// carries every deduction so it can always be explained. It is a pure,
// deterministic function: the service and the agent's local CLI call the
// same code and get the same score for the same input.
package health

import (
	"math"
	"sort"
)

// Algo names this version of the rules. Changing a weight or a threshold
// means a new version.
//
// v2 (spec v1.1 delta 10.5): brute force and spray deduct once per server
// (5, or 8 while root may use a password) instead of 3 per event, and an
// open db_public_access deducts 8.
//
// v3 (xnux-pm specs/05 §8.5, §14.1, decisions L16, L24): event items are one
// deduction per event, with its state and what resolving it would give
// back; an event resolved by hand but still failing deducts half; a
// recurrence within 7 days deducts 1.5 times; accepted (suppressed) items
// deduct nothing; ssh_root_password_login only counts as "seen in 24 h";
// an open docker_api_access caps the score at 20.
const Algo = "health/v3"

// Dimensions.
const (
	DimStability = "stability"
	DimResources = "resources"
	DimCapacity  = "capacity"
	DimSecurity  = "security"
	DimHardware  = "hardware"
)

// Levels.
const (
	LevelHealthy  = "healthy"  // 90–100
	LevelNotice   = "notice"   // 70–89
	LevelRisk     = "risk"     // 40–69
	LevelCritical = "critical" // 0–39
)

// Event states (C-API-HEALTH deductions[].state).
const (
	StateOpen             = "open"              // needs handling
	StateInProgress       = "in_progress"       // acknowledged: someone is on it
	StateAwaitingRecovery = "awaiting_recovery" // resolved by hand, still failing
)

// Event is an event that costs points: in progress and not suppressed, or
// resolved by hand while still failing (awaiting recovery).
type Event struct {
	ID       string
	Type     string
	Severity int // 0 = P0
	State    string
	Subject  string // a unit, a port… shown with the item
	// Recurrent: it recurs within 7 days of the previous one ending (L16):
	// its event item deducts 1.5 times.
	Recurrent bool
	// Count24h and Count1h are its occurrences included in the 24-hour and
	// 1-hour counts of Input: resolving it takes them out.
	Count24h, Count1h int
	// StillFailing: the agent still reports it failing (a unit in the
	// failed list), so resolving it by hand leaves it awaiting recovery.
	StillFailing bool
}

// Accept is an item the user accepted (a suppression, delta 13.6): it is
// listed instead of deducted. An empty Subject matches any subject.
type Accept struct {
	Item    string `json:"item"`
	Subject string `json:"subject,omitempty"`
}

// Input is what the score is computed from. Resource figures are P95 (P5
// for available memory) over the last hour of 1-minute aggregates; counts
// are occurrences in the last 24 hours (by when they happened), without
// those of events the user resolved. A nil pointer means the host has no
// such data (no swap, no sensors), and that item deducts nothing.
type Input struct {
	// Events that cost points by themselves (see Event).
	Events []Event
	// Accepted items deduct nothing (see Accept).
	Accepted []Accept

	// Stability
	OOM24h            int
	ServiceCrashes24h int // service_failed occurrences, recovered on their own or not
	Segfaults24h      int

	// Resource pressure
	CPUP95         *float64 // %
	MemAvailP5     *float64 // % of total
	SwapInP95      *float64 // pages/s
	IOWaitP95      *float64 // %
	LoadPerCoreP95 *float64 // load1 / cores

	// Capacity
	DiskDaysToFull *float64 // the soonest mount
	DiskDaysMount  string
	DiskUsedMax    *float64 // % on the fullest mount
	DiskUsedMount  string
	InodeUsedMax   *float64 // %
	InodeMount     string

	// Security
	RootPasswordLogin bool // ssh_root_password_login within 24h

	// Hardware and kernel
	TempMaxP95  *float64 // °C, hottest sensor
	HungTask24h int

	// Hard caps
	OOM1h       int      // OOM kills in the last hour
	MemAvailNow *float64 // % of total, latest minute

	// Maintenance (suggestions only, never deducted)
	AgentOutdated bool
}

// Deduction is one item that cost points.
type Deduction struct {
	Dim     string  `json:"dim"`
	Item    string  `json:"item"`
	Value   float64 `json:"value"`
	Deduct  float64 `json:"deduct"`
	Subject string  `json:"subject,omitempty"` // a mount point or a unit, when the item has one
	// EventID, State and Gain: the event behind the item, its state and the
	// points resolving it would give back (v3).
	EventID string `json:"event_id,omitempty"`
	State   string `json:"state,omitempty"`
	Gain    int    `json:"gain_if_resolved,omitempty"`
}

// Cap is a hard ceiling that applied.
type Cap struct {
	Item    string `json:"item"`
	Limit   int    `json:"limit"`
	EventID string `json:"event_id,omitempty"`
	State   string `json:"state,omitempty"`
	Gain    int    `json:"gain_if_resolved,omitempty"`
}

// Result is a score with its explanation.
type Result struct {
	Score       int         `json:"score"`
	Level       string      `json:"level"`
	Algo        string      `json:"algo"`
	Deductions  []Deduction `json:"deductions"`            // largest first
	Cap         *Cap        `json:"cap,omitempty"`         // the lowest ceiling that applied
	Accepted    []Accept    `json:"accepted,omitempty"`    // items the user accepted, not deducted
	Suggestions []string    `json:"suggestions,omitempty"` // maintenance hints, not scored
}

// linear deducts 0 at from and max at to, in proportion between; from and
// to may run either way (to < from for "lower is worse").
func linear(v, from, to, max float64) float64 {
	t := (v - from) / (to - from)
	switch {
	case t <= 0:
		return 0
	case t >= 1:
		return max
	}
	return t * max
}

type item struct {
	dim     string
	name    string
	value   float64
	deduct  float64
	subject string
	ev      *Event
}

// dimension caps (spec delta 8.2).
var dimMax = map[string]float64{
	DimStability: 30, DimResources: 25, DimCapacity: 20, DimSecurity: 20, DimHardware: 5,
}

// Event types by how they cost points.
var (
	serviceTypes  = map[string]bool{"service_failed": true, "service_start_failed": true}
	securityTypes = map[string]bool{"sudo_sensitive": true, "sudo_auth_fail": true, "su_root": true, "user_created": true,
		"proc_fileless": true, "proc_deleted_exe": true, "proc_stale_binary": true, "proc_tmp_exec": true}
	attackTypes    = map[string]bool{"ssh_bruteforce": true, "ssh_spray": true}
	intrusionTypes = map[string]bool{"ssh_breach": true, "proc_reverse_shell": true}
	diskTypes      = map[string]bool{"disk_error": true, "fs_readonly": true}
	// countOf names the 24-hour count an event type's occurrences are in.
	countOf = map[string]string{"oom_kill": "oom_24h", "service_failed": "service_crashes_24h",
		"proc_segfault": "segfaults_24h", "hung_task": "hung_task_24h"}
)

// weight is what an event item deducts, given its base: half while
// awaiting recovery, 1.5 times for a recurrence.
func weight(e *Event, base float64) float64 {
	if e.State == StateAwaitingRecovery {
		base /= 2
	}
	if e.Recurrent {
		base *= 1.5
	}
	return base
}

// Score computes the health of one server, with what resolving each of its
// events would give back.
func Score(in Input) Result {
	res := score(in)
	gain := map[string]int{}
	for i := range in.Events {
		gain[in.Events[i].ID] = max(0, score(without(in, i)).Score-res.Score)
	}
	for i := range res.Deductions {
		if id := res.Deductions[i].EventID; id != "" {
			res.Deductions[i].Gain = gain[id]
		}
	}
	if res.Cap != nil && res.Cap.EventID != "" {
		res.Cap.Gain = gain[res.Cap.EventID]
	}
	return res
}

// without is in as if event i were resolved by the user: gone, or awaiting
// recovery while still failing, with its occurrences out of the counts.
// The gain is then exactly what the user's action changes (L23).
func without(in Input, i int) Input {
	e := in.Events[i]
	out := in
	out.Events = append(append([]Event(nil), in.Events[:i]...), in.Events[i+1:]...)
	if e.StillFailing && e.State != StateAwaitingRecovery {
		a := e
		a.State, a.Count24h, a.Count1h = StateAwaitingRecovery, 0, 0
		out.Events = append(out.Events, a)
	}
	switch countOf[e.Type] {
	case "oom_24h":
		out.OOM24h, out.OOM1h = max(0, out.OOM24h-e.Count24h), max(0, out.OOM1h-e.Count1h)
	case "service_crashes_24h":
		out.ServiceCrashes24h = max(0, out.ServiceCrashes24h-e.Count24h)
	case "segfaults_24h":
		out.Segfaults24h = max(0, out.Segfaults24h-e.Count24h)
	case "hung_task_24h":
		out.HungTask24h = max(0, out.HungTask24h-e.Count24h)
	}
	return out
}

func score(in Input) Result {
	var items []item
	var accepted []Accept
	isAccepted := func(name, subject string) bool {
		for _, a := range in.Accepted {
			if a.Item == name && (a.Subject == "" || a.Subject == subject) {
				return true
			}
		}
		return false
	}
	addEv := func(dim, name string, value, deduct float64, subject string, ev *Event) {
		if deduct <= 0 {
			return
		}
		if isAccepted(name, subject) {
			accepted = append(accepted, Accept{Item: name, Subject: subject})
			return
		}
		items = append(items, item{dim, name, value, deduct, subject, ev})
	}
	add := func(dim, name string, value, deduct float64, subject string) {
		addEv(dim, name, value, deduct, subject, nil)
	}
	// The event behind a count item: the one still going on with the most
	// occurrences in it.
	behind := func(count string) *Event {
		var best *Event
		for i := range in.Events {
			e := &in.Events[i]
			if countOf[e.Type] == count && e.State != StateAwaitingRecovery && (best == nil || e.Count24h > best.Count24h) {
				best = e
			}
		}
		return best
	}
	// Counts deduct from the start point on: the spec's start point N is
	// passed as N-1, so the Nth occurrence already costs points (one OOM
	// costs 3 of 15; the third segfault costs 5/18 of 5).
	count := func(dim, name string, n int, from, to, max float64) {
		if n > 0 {
			addEv(dim, name, float64(n), linear(float64(n), from, to, max), "", behind(name))
		}
	}
	opt := func(dim, name string, v *float64, from, to, max float64, subject string) {
		if v != nil {
			add(dim, name, *v, linear(*v, from, to, max), subject)
		}
	}

	// Events, one item each; some set a ceiling instead.
	var attack *Event
	var caps []Cap
	capFor := func(name string, limit int, e *Event) {
		caps = append(caps, Cap{Item: name, Limit: limit, EventID: e.ID, State: e.State})
	}
	for i := range in.Events {
		e := &in.Events[i]
		switch {
		case serviceTypes[e.Type]:
			addEv(DimStability, "open_service_failed", 1, weight(e, 10), e.Subject, e)
		case securityTypes[e.Type] && e.Severity == 1:
			addEv(DimSecurity, "open_p1_security", 1, weight(e, 8), e.Subject, e)
		case securityTypes[e.Type] && e.Severity == 2:
			addEv(DimSecurity, "open_p2_security", 1, weight(e, 3), e.Subject, e)
		case attackTypes[e.Type]:
			if attack == nil || e.Severity < attack.Severity {
				attack = e
			}
		case e.Type == "db_public_access":
			addEv(DimSecurity, "open_db_public_access", 1, weight(e, 8), e.Subject, e)
		case intrusionTypes[e.Type]:
			capFor("open_p0_intrusion", 20, e)
		case e.Type == "docker_api_access":
			capFor("open_docker_api", 20, e)
		case diskTypes[e.Type]:
			capFor("open_disk_failure", 40, e)
		}
	}

	// Stability (30)
	count(DimStability, "oom_24h", in.OOM24h, 0, 5, 15)
	count(DimStability, "service_crashes_24h", in.ServiceCrashes24h, 0, 10, 10)
	count(DimStability, "segfaults_24h", in.Segfaults24h, 2, 20, 5)

	// Resource pressure (25)
	opt(DimResources, "cpu_p95", in.CPUP95, 80, 98, 10, "")
	opt(DimResources, "mem_avail_p5", in.MemAvailP5, 20, 5, 10, "")
	opt(DimResources, "swap_in_p95", in.SwapInP95, 10, 200, 8, "")
	opt(DimResources, "iowait_p95", in.IOWaitP95, 10, 40, 5, "")
	opt(DimResources, "load_per_core_p95", in.LoadPerCoreP95, 1, 3, 5, "")

	// Capacity (20)
	opt(DimCapacity, "disk_days_to_full", in.DiskDaysToFull, 30, 2, 15, in.DiskDaysMount)
	opt(DimCapacity, "disk_used_pct", in.DiskUsedMax, 80, 97, 10, in.DiskUsedMount)
	opt(DimCapacity, "inode_used_pct", in.InodeUsedMax, 80, 97, 8, in.InodeMount)

	// Security (20)
	if in.RootPasswordLogin {
		add(DimSecurity, "root_password_login", 1, 5, "")
	}
	if attack != nil {
		if attack.Severity <= 1 {
			addEv(DimSecurity, "open_ssh_attack_root", 1, weight(attack, 8), "", attack)
		} else {
			addEv(DimSecurity, "open_ssh_attack", 1, weight(attack, 5), "", attack)
		}
	}

	// Hardware and kernel (5)
	opt(DimHardware, "temp_p95", in.TempMaxP95, 75, 95, 3, "")
	count(DimHardware, "hung_task_24h", in.HungTask24h, 0, 5, 3)

	// Each dimension is capped; items within it are scaled down together
	// so the explanation still adds up to what was deducted.
	perDim := map[string]float64{}
	for _, it := range items {
		perDim[it.dim] += it.deduct
	}
	res := Result{Algo: Algo, Deductions: []Deduction{}, Accepted: accepted}
	total := 0.0
	for _, it := range items {
		d := it.deduct
		if sum := perDim[it.dim]; sum > dimMax[it.dim] {
			d = d * dimMax[it.dim] / sum
		}
		d = math.Round(d*10) / 10
		total += d
		ded := Deduction{Dim: it.dim, Item: it.name, Value: math.Round(it.value*10) / 10, Deduct: d, Subject: it.subject}
		if it.ev != nil {
			ded.EventID, ded.State = it.ev.ID, it.ev.State
		}
		res.Deductions = append(res.Deductions, ded)
	}
	sort.SliceStable(res.Deductions, func(i, j int) bool { return res.Deductions[i].Deduct > res.Deductions[j].Deduct })

	score := int(math.Round(100 - total))

	// Hard caps (spec delta 8.3): the lowest that applies wins. Accepting
	// items never lifts one.
	if (in.DiskDaysToFull != nil && *in.DiskDaysToFull < 1) || (in.DiskUsedMax != nil && *in.DiskUsedMax >= 99) {
		caps = append(caps, Cap{Item: "disk_full_imminent", Limit: 40})
	}
	if in.OOM1h > 0 && in.MemAvailNow != nil && *in.MemAvailNow < 5 {
		caps = append(caps, Cap{Item: "oom_memory_exhausted", Limit: 50})
	}
	for i := range caps {
		if score > caps[i].Limit && (res.Cap == nil || caps[i].Limit < res.Cap.Limit) {
			c := caps[i]
			res.Cap = &c
		}
	}
	if res.Cap != nil {
		score = res.Cap.Limit
	}
	res.Score = max(0, min(100, score))
	res.Level = LevelOf(res.Score)

	if in.AgentOutdated {
		res.Suggestions = append(res.Suggestions, "agent_outdated")
	}
	return res
}

// LevelOf maps a score to its level.
func LevelOf(score int) string {
	switch {
	case score >= 90:
		return LevelHealthy
	case score >= 70:
		return LevelNotice
	case score >= 40:
		return LevelRisk
	}
	return LevelCritical
}

// Top is the deduction to show when there is room for one reason: the
// ceiling that applied, else the largest deduction; "" when healthy.
func (r Result) Top() string {
	if r.Cap != nil {
		return r.Cap.Item
	}
	if len(r.Deductions) > 0 {
		return r.Deductions[0].Item
	}
	return ""
}
