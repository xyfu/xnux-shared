package proto

import (
	"strconv"
	"strings"
	"time"
)

// Attention is how much of a person's attention an event asks for (xnux-pm
// specs/07 §1). It alone decides whether an event is pushed; the severity
// only decides how loudly. It rises over time (record → todo → push) and
// never falls back on its own.
const (
	AttentionPush   = "push"   // urgent: broken, or someone got in; pushed
	AttentionTodo   = "todo"   // to do, not urgent; not pushed (but see PushOnce)
	AttentionRecord = "record" // background; hidden from the lists by default
)

// AttentionRank orders the layers: a higher rank wins.
func AttentionRank(a string) int {
	switch a {
	case AttentionPush:
		return 2
	case AttentionTodo:
		return 1
	}
	return 0
}

// The numbers of the rules (specs/07 R1–R4), tuned later by the handling
// rate; server and clients share them.
const (
	CrashGrace           = 2 * time.Minute    // a crash that recovers within it stays a record
	SustainedTodo        = 30 * time.Minute   // a lasting resource problem becomes a to-do
	RepeatCount          = 3                  // the third occurrence within RepeatWindow is a to-do
	RepeatWindow         = 24 * time.Hour     //
	SSLUrgentDays        = 3                  // a certificate with fewer days left is urgent
	SSHExposureQuiet     = 72 * time.Hour     // ssh_exposure ends without attacks this long
	ServiceUnstableQuiet = 7 * 24 * time.Hour // service_unstable ends without crashes this long
	RestartPendingMax    = 20                 // members listed in restart_pending
)

// Server-generated to-dos (specs/07 R2–R4).
const (
	EventSSHExposure     = "ssh_exposure"     // password login is accepted and being tried
	EventRestartPending  = "restart_pending"  // programs not restarted after an upgrade
	EventServiceUnstable = "service_unstable" // one unit crashed 3 times in 24 hours
)

// How an attention layer moves (specs/07 R1).
const (
	RiseNone    = ""        // stays at its base layer
	RiseGrace   = "grace"   // record during CrashGrace, then push while still failing
	RiseSustain = "sustain" // record, todo after SustainedTodo; push at the warning line (P1)
	RiseRepeat  = "repeat"  // record, todo at the RepeatCount-th occurrence within RepeatWindow
	RiseSSL     = "ssl"     // todo, push under SSLUrgentDays left
)

// AttentionRule is a type's layer and how it moves.
type AttentionRule struct {
	Base     string
	Rise     string
	PushOnce bool // a to-do pushed once, when it is created (not on recurrence or reopening)
}

// Attention is the layer table (specs/07 R1). A type that is missing is
// urgent, as everything was before the layers.
var Attention = map[string]AttentionRule{
	EventServiceFailed:      {AttentionRecord, RiseGrace, false},
	EventServiceStartFailed: {AttentionRecord, RiseGrace, false},
	EventAgentOffline:       {AttentionPush, RiseNone, false},
	EventCheckDown:          {AttentionPush, RiseNone, false},
	EventResourceThreshold:  {AttentionRecord, RiseSustain, false},
	EventSwapThrashing:      {AttentionRecord, RiseSustain, false},
	EventMemPressure:        {AttentionRecord, RiseSustain, false},
	EventOOMKill:            {AttentionRecord, RiseRepeat, false},
	EventProcSegfault:       {AttentionRecord, RiseRepeat, false},
	EventHungTask:           {AttentionRecord, RiseRepeat, false},
	EventSSLExpiring:        {AttentionTodo, RiseSSL, false},
	EventAgentOutdated:      {AttentionRecord, RiseNone, false}, // security: todo, pushed once (AttentionOf)
	EventDBPublicAccess:     {AttentionTodo, RiseNone, true},

	EventSSHBruteforce: {AttentionRecord, RiseNone, false},
	EventSSHSpray:      {AttentionRecord, RiseNone, false},
	EventSSHTargeted:   {AttentionRecord, RiseNone, false},
	EventSudoAuthFail:  {AttentionRecord, RiseNone, false},
	EventSuRoot:        {AttentionRecord, RiseNone, false},

	EventSSHBreach:            {AttentionPush, RiseNone, false},
	EventDockerAPIAccess:      {AttentionPush, RiseNone, false},
	EventProcReverseShell:     {AttentionPush, RiseNone, false},
	EventProcFileless:         {AttentionPush, RiseNone, false},
	EventProcTmpExec:          {AttentionPush, RiseNone, false},
	EventProcDeletedExe:       {AttentionPush, RiseNone, false}, // system paths: record (AttentionOf)
	EventProcStaleBinary:      {AttentionRecord, RiseNone, false},
	EventDiskError:            {AttentionPush, RiseNone, false},
	EventFSReadonly:           {AttentionPush, RiseNone, false},
	EventSSHRootPasswordLogin: {AttentionPush, RiseNone, false},
	EventSudoSensitive:        {AttentionPush, RiseNone, false},
	EventUserCreated:          {AttentionPush, RiseNone, false},

	EventSSHExposure:     {AttentionTodo, RiseNone, false},
	EventRestartPending:  {AttentionTodo, RiseNone, false},
	EventServiceUnstable: {AttentionTodo, RiseNone, false},
}

// systemDirs are where package managers install programs (specs/07 R1).
var systemDirs = []string{"/usr/", "/bin/", "/sbin/", "/lib/", "/lib64/"}

// SystemPath reports whether exe ("…" or "… (deleted)") lies in a system
// directory: an upgraded program still running from its old file.
func SystemPath(exe string) bool {
	exe = strings.TrimSuffix(exe, " (deleted)")
	for _, d := range systemDirs {
		if strings.HasPrefix(exe, d) {
			return true
		}
	}
	return false
}

// AttentionState is what the layer of an event depends on, besides its type.
type AttentionState struct {
	Type     string
	Severity int            // 0 = P0
	Data     map[string]any // the event's data
	// Age is how long the event has been going on (since it was created or
	// reopened); Failing: a crashed unit has not recovered yet.
	Age     time.Duration
	Failing bool
	// Recent is the occurrences of the event within RepeatWindow.
	Recent int
}

// AttentionOf computes the layer of an event now. Callers keep the higher
// of this and the stored layer: attention never falls on its own.
func AttentionOf(s AttentionState) string {
	r, ok := Attention[s.Type]
	if !ok {
		return AttentionPush
	}
	switch s.Type {
	case EventAgentOutdated:
		if dataString(s.Data, "level") == LevelSecurity {
			return AttentionTodo
		}
		return AttentionRecord
	case EventProcDeletedExe:
		if SystemPath(dataString(s.Data, "exe")) {
			return AttentionRecord
		}
		return AttentionPush
	}
	switch r.Rise {
	case RiseGrace:
		if s.Failing && s.Age >= CrashGrace {
			return AttentionPush
		}
	case RiseSustain:
		if s.Type == EventResourceThreshold && s.Severity <= 1 {
			return AttentionPush // the warning line
		}
		if s.Age >= SustainedTodo {
			return AttentionTodo
		}
	case RiseRepeat:
		if s.Recent >= RepeatCount {
			return AttentionTodo
		}
	case RiseSSL:
		if days, err := strconv.ParseFloat(dataString(s.Data, "days_left"), 64); err == nil && days < SSLUrgentDays {
			return AttentionPush
		}
	}
	return r.Base
}

// PushOnce reports whether a to-do of this kind is pushed once when it is
// created (specs/07 R1).
func PushOnce(typ string, data map[string]any) bool {
	if typ == EventAgentOutdated {
		return dataString(data, "level") == LevelSecurity
	}
	return Attention[typ].PushOnce
}
