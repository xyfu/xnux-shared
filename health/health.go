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
const Algo = "health/v1"

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

// Input is what the score is computed from. Resource figures are P95 (P5
// for available memory) over the last hour of 1-minute aggregates; counts
// are over the last 24 hours unless named "Open" (unresolved now). A nil
// pointer means the host has no such data (no swap, no sensors), and that
// item deducts nothing.
type Input struct {
	// Stability
	OpenServiceFailed int // unresolved service_failed events
	OOM24h            int
	ServiceCrashes24h int // service_failed events in 24h, recovered or not
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
	OpenP1Security    int  // unresolved P1 security events
	OpenP2Security    int  // unresolved P2 security events
	RootPasswordLogin bool // ssh_root_password_login within 24h

	// Hardware and kernel
	TempMaxP95  *float64 // °C, hottest sensor
	HungTask24h int

	// Hard caps
	OpenP0Intrusion int      // unresolved ssh_breach or proc_reverse_shell
	OpenDiskFailure int      // unresolved disk_error or fs_readonly
	OOM1h           int      // OOM kills in the last hour
	MemAvailNow     *float64 // % of total, latest minute

	// Maintenance (suggestions only, never deducted)
	AgentOutdated bool
}

// Deduction is one item that cost points.
type Deduction struct {
	Dim     string  `json:"dim"`
	Item    string  `json:"item"`
	Value   float64 `json:"value"`
	Deduct  float64 `json:"deduct"`
	Subject string  `json:"subject,omitempty"` // a mount point, when the item has one
}

// Cap is a hard ceiling that applied.
type Cap struct {
	Item  string `json:"item"`
	Limit int    `json:"limit"`
}

// Result is a score with its explanation.
type Result struct {
	Score       int         `json:"score"`
	Level       string      `json:"level"`
	Algo        string      `json:"algo"`
	Deductions  []Deduction `json:"deductions"`            // largest first
	Cap         *Cap        `json:"cap,omitempty"`         // the lowest ceiling that applied
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
}

// dimension caps (spec delta 8.2).
var dimMax = map[string]float64{
	DimStability: 30, DimResources: 25, DimCapacity: 20, DimSecurity: 20, DimHardware: 5,
}

// Score computes the health of one server.
func Score(in Input) Result {
	var items []item
	add := func(dim, name string, value, deduct float64, subject string) {
		if deduct > 0 {
			items = append(items, item{dim, name, value, deduct, subject})
		}
	}
	// Counts deduct from the start point on: the spec's start point N is
	// passed as N-1, so the Nth occurrence already costs points (one OOM
	// costs 3 of 15; the third segfault costs 5/18 of 5).
	count := func(dim, name string, n int, from, to, max float64) {
		if n > 0 {
			add(dim, name, float64(n), linear(float64(n), from, to, max), "")
		}
	}
	opt := func(dim, name string, v *float64, from, to, max float64, subject string) {
		if v != nil {
			add(dim, name, *v, linear(*v, from, to, max), subject)
		}
	}

	// Stability (30)
	if in.OpenServiceFailed > 0 {
		add(DimStability, "open_service_failed", float64(in.OpenServiceFailed), 10*float64(in.OpenServiceFailed), "")
	}
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
	if in.OpenP1Security > 0 {
		add(DimSecurity, "open_p1_security", float64(in.OpenP1Security), 8*float64(in.OpenP1Security), "")
	}
	if in.OpenP2Security > 0 {
		add(DimSecurity, "open_p2_security", float64(in.OpenP2Security), 3*float64(in.OpenP2Security), "")
	}
	if in.RootPasswordLogin {
		add(DimSecurity, "root_password_login", 1, 5, "")
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
	res := Result{Algo: Algo, Deductions: []Deduction{}}
	total := 0.0
	for _, it := range items {
		d := it.deduct
		if sum := perDim[it.dim]; sum > dimMax[it.dim] {
			d = d * dimMax[it.dim] / sum
		}
		d = math.Round(d*10) / 10
		total += d
		res.Deductions = append(res.Deductions, Deduction{
			Dim: it.dim, Item: it.name, Value: math.Round(it.value*10) / 10, Deduct: d, Subject: it.subject,
		})
	}
	sort.SliceStable(res.Deductions, func(i, j int) bool { return res.Deductions[i].Deduct > res.Deductions[j].Deduct })

	score := int(math.Round(100 - total))

	// Hard caps (spec delta 8.3): the lowest that applies wins.
	caps := []Cap{}
	if in.OpenP0Intrusion > 0 {
		caps = append(caps, Cap{"open_p0_intrusion", 20})
	}
	if in.OpenDiskFailure > 0 {
		caps = append(caps, Cap{"open_disk_failure", 40})
	}
	if (in.DiskDaysToFull != nil && *in.DiskDaysToFull < 1) || (in.DiskUsedMax != nil && *in.DiskUsedMax >= 99) {
		caps = append(caps, Cap{"disk_full_imminent", 40})
	}
	if in.OOM1h > 0 && in.MemAvailNow != nil && *in.MemAvailNow < 5 {
		caps = append(caps, Cap{"oom_memory_exhausted", 50})
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
