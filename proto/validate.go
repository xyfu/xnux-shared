package proto

import (
	"errors"
	"fmt"
	"math"
	"regexp"
)

// Limits shared by agent and server.
const (
	MaxMetricsPerPayload = 500
	MaxDisks             = 16
	MaxTemps             = 16
	MaxStringLen         = 512
)

var (
	reMachineFP = regexp.MustCompile(`^[0-9a-f]{16}$`)
	reULID      = regexp.MustCompile(`^[0-9A-HJKMNP-TV-Z]{26}$`)
	reRuleName  = regexp.MustCompile(`^[a-z0-9_]+$`)
)

// EventTypes lists the agent event types of schema v1.
var EventTypes = map[string][]string{
	EventServiceFailed:        {"unit", "result", "restarting", "n_restarts"},
	EventServiceStartFailed:   {"unit", "job_result"},
	EventServiceRecovered:     {"unit", "down_seconds"},
	EventOOMKill:              {"victim", "pid", "total_vm_mb", "anon_rss_mb", "file_rss_mb", "shmem_rss_mb", "oom_score_adj", "scope"},
	EventProcSegfault:         {"comm", "pid"},
	EventDiskError:            {"message"},
	EventFSReadonly:           {"message"},
	EventHungTask:             {"comm", "pid", "blocked_seconds"},
	EventSSHBruteforce:        {"source", "fail_count", "user_count", "window_seconds"},
	EventSSHSpray:             {"source", "fail_count", "user_count", "window_seconds"},
	EventSSHBreach:            {"source", "user", "method", "prior_failures"},
	EventSSHRootPasswordLogin: {"source"},
	EventSudoSensitive:        {"by_user", "as_user", "command"},
	EventSudoAuthFail:         {"user", "attempts"},
	EventUserCreated:          {"name", "uid"},
	EventSuRoot:               {"by_user"},
	EventProcFileless:         {"pid", "comm", "exe"},
	EventProcDeletedExe:       {"pid", "comm", "exe"},
	EventProcStaleBinary:      {"pid", "comm", "exe"},
	EventProcTmpExec:          {"pid", "comm", "exe"},
	EventProcReverseShell:     {"pid", "comm", "remote"},
	EventSwapThrashing:        {"available_mb"},
	EventMemPressure:          {"available_mb"},
	EventDBPublicAccess:       {"port", "service", "connections"},
	EventDockerAPIAccess:      {"port", "connections"},
}

// MaxTopUsers bounds security_summary.top_users.
const MaxTopUsers = 5

var severities = map[string]bool{SeverityP0: true, SeverityP1: true, SeverityP2: true, SeverityP3: true}

// ValidationError names the offending field.
type ValidationError struct {
	Field string
	Msg   string
}

func (e *ValidationError) Error() string { return e.Field + ": " + e.Msg }

func invalid(field, format string, a ...any) error {
	return &ValidationError{Field: field, Msg: fmt.Sprintf(format, a...)}
}

// Validate applies the range checks of the v1 schema on a decoded payload.
// It is the server's hot-path counterpart of ingest.v1.schema.json. JSON
// null and an absent field decode alike, so "metrics": null is accepted.
func (p *Payload) Validate() error {
	if p.V != SchemaVersion {
		return invalid("v", "unsupported schema version %d", p.V)
	}
	if p.Seq == 0 {
		return invalid("seq", "required, >= 1")
	}
	if p.Part < 0 {
		return invalid("part", "must be >= 1 when present")
	}
	if p.SentAt < 0 {
		return invalid("sent_at", "must be >= 0")
	}
	if n := len(p.AgentVersion); n == 0 || n > 64 {
		return invalid("agent_version", "length must be 1-64")
	}
	if !reMachineFP.MatchString(p.MachineFP) {
		return invalid("machine_fp", "must be 16 lowercase hex characters")
	}
	if p.Redactions == nil {
		return invalid("redactions", "required")
	}
	for k, v := range p.Redactions {
		if !reRuleName.MatchString(k) || v < 1 {
			return invalid("redactions."+k, "invalid entry")
		}
	}
	if h := p.Host; h != nil {
		if h.Hostname == "" || len(h.Hostname) > 255 || len(h.OS) > MaxStringLen || len(h.Kernel) > 128 {
			return invalid("host", "hostname, os or kernel out of range")
		}
		if h.Arch != "amd64" && h.Arch != "arm64" {
			return invalid("host.arch", "must be amd64 or arm64")
		}
	}
	if p.Metrics != nil && len(p.Metrics) == 0 {
		return invalid("metrics", "must be omitted rather than empty")
	}
	if len(p.Metrics) > MaxMetricsPerPayload {
		return invalid("metrics", "at most %d per payload", MaxMetricsPerPayload)
	}
	for i := range p.Metrics {
		if err := p.Metrics[i].validate(fmt.Sprintf("metrics[%d]", i)); err != nil {
			return err
		}
	}
	if p.Events != nil && len(p.Events) == 0 {
		return invalid("events", "must be omitted rather than empty")
	}
	for i := range p.Events {
		if err := p.Events[i].validate(fmt.Sprintf("events[%d]", i)); err != nil {
			return err
		}
	}
	if s := p.SecuritySummary; s != nil {
		if s.Start < 0 || s.End < s.Start || s.Attempts < 0 || s.RootAttempts < 0 || s.RootAttempts > s.Attempts ||
			s.Sources < 0 || s.Sources24h < 0 || len(s.TopUsers) > MaxTopUsers {
			return invalid("security_summary", "out of range")
		}
		for _, u := range s.TopUsers {
			if u.User == "" || len(u.User) > MaxStringLen || u.Count < 1 {
				return invalid("security_summary.top_users", "entry out of range")
			}
		}
	}
	return nil
}

func pctOK(v float64) bool  { return v >= 0 && v <= 100 && !math.IsNaN(v) }
func nonNeg(v float64) bool { return v >= 0 && !math.IsInf(v, 0) && !math.IsNaN(v) }

func (m *Metric) validate(f string) error {
	switch {
	case m.TS < 0:
		return invalid(f+".ts", "must be >= 0")
	case !pctOK(m.CPU.TotalPct) || !pctOK(m.CPU.IOWaitPct) || !pctOK(m.CPU.StealPct):
		return invalid(f+".cpu", "percentages must be within 0-100")
	case !nonNeg(m.Load.L1) || !nonNeg(m.Load.L5) || !nonNeg(m.Load.L15):
		return invalid(f+".load", "must be >= 0")
	case m.Mem.TotalMB < 0 || m.Mem.AvailableMB < 0 || !pctOK(m.Mem.UsedPct):
		return invalid(f+".mem", "out of range")
	}
	if s := m.Swap; s != nil && (s.TotalMB < 1 || s.UsedMB < 0 || !nonNeg(s.InPS) || !nonNeg(s.OutPS)) {
		return invalid(f+".swap", "out of range")
	}
	if n := m.Net; n != nil && (n.RxBps < 0 || n.TxBps < 0) {
		return invalid(f+".net", "must be >= 0")
	}
	if m.Disks != nil && (len(m.Disks) == 0 || len(m.Disks) > MaxDisks) {
		return invalid(f+".disks", "must hold 1-%d entries", MaxDisks)
	}
	for _, d := range m.Disks {
		if d.Mount == "" || len(d.Mount) > MaxStringLen || !nonNeg(d.TotalGB) || !nonNeg(d.FreeGB) || !pctOK(d.UsedPct) ||
			(d.InodeUsedPct != nil && !pctOK(*d.InodeUsedPct)) || (d.DaysToFull != nil && !nonNeg(*d.DaysToFull)) {
			return invalid(f+".disks", "entry out of range")
		}
	}
	if m.Temps != nil && (len(m.Temps) == 0 || len(m.Temps) > MaxTemps) {
		return invalid(f+".temps", "must hold 1-%d entries", MaxTemps)
	}
	for _, t := range m.Temps {
		if t.Name == "" || len(t.Name) > 128 || t.C < -40 || t.C > 150 {
			return invalid(f+".temps", "entry out of range")
		}
	}
	return nil
}

func (e *Event) validate(f string) error {
	required, known := EventTypes[e.Type]
	switch {
	case !reULID.MatchString(e.ID):
		return invalid(f+".id", "must be a ULID")
	case !known:
		return invalid(f+".type", "unknown event type %q", e.Type)
	case !severities[e.Severity]:
		return invalid(f+".severity", "must be P0-P3")
	case e.Count < 1:
		return invalid(f+".count", "must be >= 1")
	case e.Key == "" || len(e.Key) > MaxStringLen:
		return invalid(f+".key", "length must be 1-%d", MaxStringLen)
	case e.Data == nil:
		return invalid(f+".data", "required")
	case e.TS < 0:
		return invalid(f+".ts", "must be >= 0")
	}
	for _, k := range required {
		if _, ok := e.Data[k]; !ok {
			return invalid(f+".data."+k, "required for %s", e.Type)
		}
	}
	return nil
}

// ErrSchema is returned for payloads that do not decode at all.
var ErrSchema = errors.New("payload does not match schema v1")
