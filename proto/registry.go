package proto

import (
	"crypto/sha256"
	"encoding/hex"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
)

// Event types the server generates itself. They never travel in an ingest
// payload but share the registry with the agent's types (event lifecycle §2).
const (
	EventAgentOffline      = "agent_offline"
	EventCheckDown         = "check_down"
	EventResourceThreshold = "resource_threshold"
	EventSSLExpiring       = "ssl_expiring"
	EventAgentOutdated     = "agent_outdated"
	EventSSHTargeted       = "ssh_targeted"
)

// Event categories (spec v1.1 delta 13.2, event lifecycle §2).
const (
	CategoryState     = "A"         // a state that ends on a recovery signal
	CategoryRisk      = "B"         // a standing risk that ends after 48 quiet hours
	CategoryTransient = "C"         // a transient fault that ends after 24 quiet hours
	CategoryAction    = "D_action"  // an operation; each one is looked at by a person
	CategoryFinding   = "D_finding" // a finding of a scan or the kernel; ended by a person
	CategoryInfo      = "E"         // information that ends after 48 quiet hours
	CategorySignal    = "signal"    // not an event: it ends other events
)

// How an event ends (event lifecycle §5).
const (
	EndRecovery = "recovery"  // a recovery signal from the agent or the server
	EndMetric   = "metric"    // the server sees the metric back to normal
	EndQuiet24h = "quiet_24h" // 24 hours without a new occurrence
	EndQuiet48h = "quiet_48h" // 48 hours without a new occurrence
	EndManual   = "manual"    // only a person ends it
	EndVersion  = "version"   // the agent reports the latest version
	EndQuiet72h = "quiet_72h" // 72 hours without a new occurrence (ssh_exposure)
	EndQuiet7d  = "quiet_7d"  // 7 days without a new occurrence (service_unstable)
	EndMembers  = "members"   // when all its members ended (restart_pending)
)

// Where an event type comes from.
const (
	SourceAgent  = "agent"
	SourceServer = "server"
)

// Object names: the data fields that tell occurrences of one type apart.
// Several fields are joined with "+". Besides data fields:
const (
	ObjectServer = "server" // the server itself: the object is empty
	ObjectDay    = "day"    // the day in the account's time zone
	ObjectCheck  = "check"  // the check ID (server types)
	ObjectMetric = "metric" // the metric, plus mount point or sensor (server types)
)

// EventClass is the registry entry of one event type.
type EventClass struct {
	Category string
	Severity string // default severity
	Object   string
	End      string // empty for signals
	Source   string
}

// Registry defines every event type, agent and server alike: its category,
// object and end condition (event lifecycle §2). An agent type that is not
// registered is dropped by the server, and TestRegistry fails.
var Registry = map[string]EventClass{
	EventServiceFailed:      {CategoryState, SeverityP1, "unit", EndRecovery, SourceAgent},
	EventServiceStartFailed: {CategoryState, SeverityP1, "unit", EndRecovery, SourceAgent},
	EventAgentOffline:       {CategoryState, SeverityP1, ObjectServer, EndRecovery, SourceServer},
	EventCheckDown:          {CategoryState, SeverityP1, ObjectCheck, EndRecovery, SourceServer},
	EventResourceThreshold:  {CategoryState, SeverityP2, ObjectMetric, EndMetric, SourceServer},
	EventSwapThrashing:      {CategoryState, SeverityP2, ObjectServer, EndMetric, SourceAgent},
	EventMemPressure:        {CategoryState, SeverityP2, ObjectServer, EndMetric, SourceAgent},
	EventSSLExpiring:        {CategoryState, SeverityP2, ObjectCheck, EndMetric, SourceServer},
	EventAgentOutdated:      {CategoryState, SeverityP2, ObjectServer, EndVersion, SourceServer},

	EventSSHBruteforce:   {CategoryRisk, SeverityP2, ObjectServer, EndQuiet48h, SourceAgent},
	EventSSHSpray:        {CategoryRisk, SeverityP2, ObjectServer, EndQuiet48h, SourceAgent},
	EventDBPublicAccess:  {CategoryRisk, SeverityP1, "port", EndQuiet48h, SourceAgent},
	EventDockerAPIAccess: {CategoryRisk, SeverityP0, "port", EndQuiet48h, SourceAgent},

	EventOOMKill:      {CategoryTransient, SeverityP1, "victim", EndQuiet24h, SourceAgent},
	EventProcSegfault: {CategoryTransient, SeverityP2, "comm", EndQuiet24h, SourceAgent},
	EventHungTask:     {CategoryTransient, SeverityP2, "comm", EndQuiet24h, SourceAgent},
	EventSudoAuthFail: {CategoryTransient, SeverityP2, "user", EndQuiet24h, SourceAgent},

	EventSSHBreach:            {CategoryAction, SeverityP0, "source", EndManual, SourceAgent},
	EventSSHRootPasswordLogin: {CategoryAction, SeverityP1, "source", EndManual, SourceAgent},
	EventSudoSensitive:        {CategoryAction, SeverityP1, "by_user+command", EndManual, SourceAgent},
	EventUserCreated:          {CategoryAction, SeverityP1, "name", EndManual, SourceAgent},

	EventProcReverseShell: {CategoryFinding, SeverityP0, "exe", EndManual, SourceAgent},
	EventProcFileless:     {CategoryFinding, SeverityP1, "exe", EndManual, SourceAgent},
	EventProcTmpExec:      {CategoryFinding, SeverityP2, "exe", EndManual, SourceAgent},
	EventProcDeletedExe:   {CategoryFinding, SeverityP2, "exe", EndManual, SourceAgent},
	EventDiskError:        {CategoryFinding, SeverityP1, "device", EndManual, SourceAgent},
	EventFSReadonly:       {CategoryFinding, SeverityP1, "device", EndManual, SourceAgent},

	EventSSHTargeted:     {CategoryInfo, SeverityP3, ObjectDay, EndQuiet48h, SourceServer},
	EventProcStaleBinary: {CategoryInfo, SeverityP3, "exe", EndQuiet48h, SourceAgent},
	EventSuRoot:          {CategoryInfo, SeverityP3, "by_user+day", EndQuiet48h, SourceAgent},

	EventServiceRecovered: {CategorySignal, "", "unit", "", SourceAgent},

	// To-dos the server makes of records (specs/07 R2–R4).
	EventSSHExposure:     {CategoryRisk, SeverityP2, ObjectServer, EndQuiet72h, SourceServer},
	EventRestartPending:  {CategoryRisk, SeverityP3, ObjectServer, EndMembers, SourceServer},
	EventServiceUnstable: {CategoryTransient, SeverityP2, "unit", EndQuiet7d, SourceServer},
}

// ClientCategory is the category shown to clients: both kinds of D are "D".
func ClientCategory(category string) string {
	if category == CategoryAction || category == CategoryFinding {
		return "D"
	}
	return category
}

// Thresholds of the agent's memory rules, which the server also uses to
// decide that the condition has ended (event lifecycle §2).
const (
	SwapThrashingInPS    = 100 // pages swapped in per second
	SwapThrashingSamples = 4   // consecutive samples at or above it start the event
	MemPressureAvailPct  = 5.0 // % of memory available below which pressure starts
	MemRecoveryMinutes   = 10  // minutes the condition must stay false to end the event
	MaxObjectLen         = 256 // longer objects are replaced by a hash
	objectHashHexChars   = 16
)

// ObjectOf returns the object of an agent event: the part of the
// fingerprint that tells which unit, process, user... it is about (event
// lifecycle §2, decision L2). day is the occurrence's day in the account's
// time zone (YYYY-MM-DD), used by types whose object includes it. Server
// types (check, metric) compute their own object; "server" yields "".
func ObjectOf(typ string, data map[string]any, day string) string {
	c, ok := Registry[typ]
	if !ok {
		return ""
	}
	parts := strings.Split(c.Object, "+")
	vals := make([]string, 0, len(parts))
	for _, f := range parts {
		switch f {
		case ObjectServer, ObjectCheck, ObjectMetric:
			continue
		case ObjectDay:
			vals = append(vals, day)
		default:
			v := objectField(f, data)
			if f == "exe" && tmpObjectTypes[typ] {
				v = TmpPath(v)
			}
			vals = append(vals, v)
		}
	}
	o := strings.Join(vals, "\x1f")
	if len(o) > MaxObjectLen {
		sum := sha256.Sum256([]byte(o))
		o = hex.EncodeToString(sum[:])[:objectHashHexChars]
	}
	return o
}

// tmpObjectTypes are the process findings whose object is a path that may
// lie in a temporary directory (xnux-pm thread 0020).
var tmpObjectTypes = map[string]bool{EventProcTmpExec: true, EventProcFileless: true, EventProcDeletedExe: true}

var (
	tmpRoots   = []string{"/tmp/", "/var/tmp/", "/dev/shm/"}
	digitRun   = regexp.MustCompile(`[0-9]{3,}`)
	hexRun     = regexp.MustCompile(`^[0-9a-fA-F]{8,}$`)
	tokenSplit = regexp.MustCompile(`[^-_.]+`)
	mktempName = regexp.MustCompile(`^(tmp\.)[A-Za-z0-9]{6,}$`)
)

// TmpPath makes one program's path the same from run to run: under /tmp,
// /var/tmp and /dev/shm, the parts of directory names that look random (3
// digits or more, 8 hex digits or more, mktemp's tmp.XXXXXXXX) become "*",
// so /tmp/go-build3125544911/b001/api.test is /tmp/go-build*/b*/api.test.
// The file name itself is kept: another program stays another event.
// Other paths are returned as they are.
func TmpPath(p string) string {
	root := ""
	for _, r := range tmpRoots {
		if strings.HasPrefix(p, r) {
			root = r
			break
		}
	}
	if root == "" {
		return p
	}
	segs := strings.Split(p[len(root):], "/")
	for i := 0; i < len(segs)-1; i++ { // directories only
		if m := mktempName.FindStringSubmatch(segs[i]); m != nil {
			segs[i] = m[1] + "*"
			continue
		}
		// Piece by piece between - _ and .: a piece of hex digits only is
		// replaced whole; elsewhere runs of 3 digits or more.
		segs[i] = tokenSplit.ReplaceAllStringFunc(segs[i], func(tok string) string {
			if hexRun.MatchString(tok) && strings.ContainsAny(tok, "0123456789") {
				return "*"
			}
			return digitRun.ReplaceAllString(tok, "*")
		})
	}
	return root + strings.Join(segs, "/")
}

func objectField(f string, data map[string]any) string {
	v := dataString(data, f)
	switch f {
	case "source":
		return SourceNetwork(v)
	case "exe":
		if v == "" {
			// Agents before the lifecycle release send no exe with
			// proc_reverse_shell (decision L20): fall back to the name.
			return dataString(data, "comm")
		}
		return strings.TrimSuffix(v, " (deleted)")
	case "device":
		if v == "" {
			return "unknown"
		}
	}
	return v
}

func dataString(data map[string]any, k string) string {
	switch v := data[k].(type) {
	case string:
		return v
	case float64:
		return strconv.FormatFloat(v, 'f', -1, 64)
	case int:
		return strconv.Itoa(v)
	case int64:
		return strconv.FormatInt(v, 10)
	case bool:
		return strconv.FormatBool(v)
	case nil:
		return ""
	default:
		return ""
	}
}

// SourceNetwork reduces a source address to its network: /24 for IPv4 and
// /48 for IPv6, private and public alike; anything else (a host name) is
// returned as is. It understands addresses already masked by the redaction
// barrier, such as "203.0.113.x" and "2001:db8:85a3:x::".
func SourceNetwork(s string) string {
	if a, err := netip.ParseAddr(s); err == nil {
		bits := 48
		if a.Is4() || a.Is4In6() {
			a, bits = a.Unmap(), 24
		}
		p, _ := a.Prefix(bits)
		return p.String()
	}
	if parts := strings.Split(s, "."); len(parts) == 4 && !strings.Contains(s, ":") {
		if a, err := netip.ParseAddr(strings.Join(parts[:3], ".") + ".0"); err == nil {
			return a.String() + "/24"
		}
	}
	if strings.Contains(s, ":") {
		groups := strings.SplitN(s, ":", 4)
		if len(groups) >= 3 {
			if a, err := netip.ParseAddr(strings.Join(groups[:3], ":") + "::"); err == nil {
				p, _ := a.Prefix(48)
				return p.String()
			}
		}
	}
	return s
}
