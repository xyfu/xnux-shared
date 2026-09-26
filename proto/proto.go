// Package proto holds the ingest protocol shared by xnux-agent and xnux-server:
// the Go types of the v1 payload, protocol constants, and the embedded JSON
// Schema and redaction-marker files that the web console and tests also use.
//
// The JSON Schema (ingest.v1.schema.json) is normative; the types here must
// round-trip through it, which proto_test.go enforces.
package proto

import _ "embed"

// SchemaV1 is the JSON Schema of the v1 ingest payload.
//
//go:embed ingest.v1.schema.json
var SchemaV1 []byte

// RedactionMarkers lists the regexes that locate self-marking redaction
// placeholders in a payload (spec A6.4). The audit console highlights with them.
//
//go:embed redaction_markers.json
var RedactionMarkers []byte

// Protocol constants (spec A7).
const (
	SchemaVersion = 1

	IngestPath = "/v1/ingest"

	HeaderSeq    = "X-Xnux-Seq"
	HeaderSchema = "X-Xnux-Schema"
	HeaderRelay  = "X-Xnux-Relay"

	MaxCompressedBytes   = 512 << 10
	MaxDecompressedBytes = 4 << 20

	AgentTokenPrefix    = "xat_"
	PersonalTokenPrefix = "xpt_"
)

// Severity levels. P0 is the most severe.
const (
	SeverityP0 = "P0"
	SeverityP1 = "P1"
	SeverityP2 = "P2"
	SeverityP3 = "P3"
)

// Event types produced by the agent (spec A7.4).
const (
	EventServiceFailed        = "service_failed"
	EventServiceStartFailed   = "service_start_failed"
	EventServiceRecovered     = "service_recovered"
	EventOOMKill              = "oom_kill"
	EventProcSegfault         = "proc_segfault"
	EventDiskError            = "disk_error"
	EventFSReadonly           = "fs_readonly"
	EventHungTask             = "hung_task"
	EventSSHBruteforce        = "ssh_bruteforce"
	EventSSHSpray             = "ssh_spray"
	EventSSHBreach            = "ssh_breach"
	EventSSHRootPasswordLogin = "ssh_root_password_login" //nolint:gosec // event name, not a credential
	EventSudoSensitive        = "sudo_sensitive"
	EventSudoAuthFail         = "sudo_auth_fail"
	EventUserCreated          = "user_created"
	EventSuRoot               = "su_root"
	EventProcFileless         = "proc_fileless"
	EventProcDeletedExe       = "proc_deleted_exe"
	EventProcStaleBinary      = "proc_stale_binary"
	EventProcTmpExec          = "proc_tmp_exec"
	EventProcReverseShell     = "proc_reverse_shell"
	EventSwapThrashing        = "swap_thrashing"
	EventMemPressure          = "mem_pressure"
)

// Payload is one POST /v1/ingest request body. Fields with no data are
// omitted rather than sent as null or empty arrays.
type Payload struct {
	V            int            `json:"v"`
	Seq          uint64         `json:"seq"`
	Part         int            `json:"part,omitempty"`
	SentAt       int64          `json:"sent_at"`
	AgentVersion string         `json:"agent_version" sanitize:"trusted"`
	MachineFP    string         `json:"machine_fp"`
	Host         *Host          `json:"host,omitempty"`
	Metrics      []Metric       `json:"metrics,omitempty"`
	Events       []Event        `json:"events,omitempty"`
	Diag         *Diag          `json:"diag,omitempty"`
	Redactions   map[string]int `json:"redactions"`
}

// Host is sent at start-up, every 6 hours and whenever it changes (spec A2.7).
type Host struct {
	Hostname     string   `json:"hostname"`
	OS           string   `json:"os" sanitize:"trusted"`
	Kernel       string   `json:"kernel" sanitize:"trusted"`
	Arch         string   `json:"arch"`
	Cores        int      `json:"cores,omitempty"`
	Uptime       int64    `json:"uptime,omitempty"`
	Virt         string   `json:"virt,omitempty"`
	Capabilities []string `json:"capabilities,omitempty"`
}

// Metric is one sampling tick; all fields share TS.
type Metric struct {
	TS    int64  `json:"ts"`
	CPU   CPU    `json:"cpu"`
	Load  Load   `json:"load"`
	Mem   Mem    `json:"mem"`
	Swap  *Swap  `json:"swap,omitempty"`
	Disks []Disk `json:"disks,omitempty"`
	Temps []Temp `json:"temps,omitempty"`
}

type CPU struct {
	TotalPct  float64 `json:"total_pct"`
	IOWaitPct float64 `json:"iowait_pct"`
	StealPct  float64 `json:"steal_pct"`
}

type Load struct {
	L1  float64 `json:"l1"`
	L5  float64 `json:"l5"`
	L15 float64 `json:"l15"`
}

type Mem struct {
	TotalMB     int     `json:"total_mb"`
	AvailableMB int     `json:"available_mb"`
	UsedPct     float64 `json:"used_pct"`
}

// Swap is omitted entirely when the host has no swap.
type Swap struct {
	TotalMB int     `json:"total_mb"`
	UsedMB  int     `json:"used_mb"`
	InPS    float64 `json:"in_ps"`
	OutPS   float64 `json:"out_ps"`
}

type Disk struct {
	Mount        string   `json:"mount"`
	FS           string   `json:"fs"`
	TotalGB      float64  `json:"total_gb"`
	FreeGB       float64  `json:"free_gb"`
	UsedPct      float64  `json:"used_pct"`
	InodeUsedPct *float64 `json:"inode_used_pct,omitempty"`
	GrowthMBH    *float64 `json:"growth_mb_h,omitempty"`
	DaysToFull   *float64 `json:"days_to_full,omitempty"`
}

type Temp struct {
	Name string  `json:"name"`
	C    float64 `json:"c"`
}

// Struct tag `sanitize:"trusted"` marks agent-generated fields for which the
// agent's redaction barrier skips the IP rules.

// Event is a normalized event (spec A4.6). The same ID arriving again is an
// update of that event. Data fields per type are defined in the JSON Schema.
type Event struct {
	ID         string         `json:"id"`
	TS         int64          `json:"ts"`
	LastTS     int64          `json:"last_ts,omitempty"`
	Type       string         `json:"type"`
	Severity   string         `json:"severity"`
	Count      int            `json:"count"`
	Key        string         `json:"key"`
	Data       map[string]any `json:"data"`
	Snapshot   *Snapshot      `json:"snapshot,omitempty"`
	TSAdjusted bool           `json:"ts_adjusted,omitempty"`
}

// Snapshot is the on-site context attached to P0/P1 and selected events (spec A4.5).
type Snapshot struct {
	Series *SnapshotSeries `json:"series,omitempty"`
	TopRSS []Process       `json:"top_rss,omitempty"`
	TopCPU []Process       `json:"top_cpu,omitempty"`
}

// SnapshotSeries holds the last 10 minutes of metrics; nil entries are gaps.
type SnapshotSeries struct {
	Step       int        `json:"step"`
	CPUTotal   []*float64 `json:"cpu_total,omitempty"`
	MemUsedPct []*float64 `json:"mem_used_pct,omitempty"`
	SwapUsedMB []*float64 `json:"swap_used_mb,omitempty"`
	Load1      []*float64 `json:"load1,omitempty"`
}

type Process struct {
	PID     int     `json:"pid"`
	Comm    string  `json:"comm"`
	Cmdline string  `json:"cmdline,omitempty"`
	UID     *int    `json:"uid,omitempty"`
	RSSMB   float64 `json:"rss_mb,omitempty"`
	CPUPct  float64 `json:"cpu_pct,omitempty"`
	Unit    string  `json:"unit,omitempty"`
}

// Diag is the agent's self-diagnostics.
type Diag struct {
	RSSMB           float64        `json:"rss_mb"`
	SpoolMB         float64        `json:"spool_mb"`
	KmsgLost        int64          `json:"kmsg_lost"`
	DroppedMetrics  int64          `json:"dropped_metrics"`
	CollectorErrors map[string]int `json:"collector_errors,omitempty"`
}

// IngestResponse is the body of a 202 reply (spec A7.2). The agent never
// changes behavior based on it.
type IngestResponse struct {
	AckSeq     uint64 `json:"ack_seq"`
	ServerTime int64  `json:"server_time"`
	Notice     string `json:"notice,omitempty"`
}

// Notices the server may attach to IngestResponse.
const (
	NoticeAgentOutdated = "agent_outdated"
	NoticeClockSkew     = "clock_skew"
)
