package sanitize

import (
	"bytes"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/xyfu/xnux-shared/proto"
)

var update = flag.Bool("update", false, "rewrite testdata/*.want from the current rules")

const caseSep = "\n---\n"

func newBarrier(t testing.TB) *Barrier {
	t.Helper()
	b, err := New(Options{MaskEmail: true})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// TestGoldenCorpus runs every testdata/*.in case through the barrier and
// compares with the matching *.want. Cases are separated by "---" lines.
func TestGoldenCorpus(t *testing.T) {
	b := newBarrier(t)
	ins, _ := filepath.Glob("testdata/*.in")
	if len(ins) == 0 {
		t.Fatal("no corpus")
	}
	for _, in := range ins {
		name := strings.TrimSuffix(filepath.Base(in), ".in")
		t.Run(name, func(t *testing.T) {
			raw, err := os.ReadFile(in)
			if err != nil {
				t.Fatal(err)
			}
			cases := strings.Split(strings.TrimSuffix(string(raw), "\n"), caseSep)
			got := make([]string, len(cases))
			for i, c := range cases {
				got[i] = b.String(c)
			}
			wantPath := strings.TrimSuffix(in, ".in") + ".want"
			if *update {
				if err := os.WriteFile(wantPath, []byte(strings.Join(got, caseSep)+"\n"), 0o644); err != nil {
					t.Fatal(err)
				}
				return
			}
			wantRaw, err := os.ReadFile(wantPath)
			if err != nil {
				t.Fatal(err)
			}
			want := strings.Split(strings.TrimSuffix(string(wantRaw), "\n"), caseSep)
			if len(want) != len(cases) {
				t.Fatalf("%d cases in .in, %d in .want", len(cases), len(want))
			}
			for i := range cases {
				if got[i] != want[i] {
					t.Errorf("case %d\n in:   %q\n got:  %q\n want: %q", i+1, cases[i], got[i], want[i])
				}
				if again := b.String(got[i]); again != got[i] {
					t.Errorf("case %d not idempotent\n once:  %q\n twice: %q", i+1, got[i], again)
				}
			}
		})
	}
}

// TestLeakGuard checks no sensitive substring listed in secrets.txt survives.
func TestLeakGuard(t *testing.T) {
	b := newBarrier(t)
	secretsRaw, err := os.ReadFile("testdata/secrets.txt")
	if err != nil {
		t.Fatal(err)
	}
	var secrets []string
	for _, s := range strings.Split(string(secretsRaw), "\n") {
		if s = strings.TrimSpace(s); s != "" {
			secrets = append(secrets, s)
		}
	}
	ins, _ := filepath.Glob("testdata/*.in")
	var out strings.Builder
	for _, in := range ins {
		raw, _ := os.ReadFile(in)
		for _, c := range strings.Split(string(raw), caseSep) {
			out.WriteString(b.String(c))
			out.WriteByte('\n')
		}
	}
	all := out.String()
	for _, s := range secrets {
		if strings.Contains(all, s) {
			t.Errorf("secret %q leaked", s)
		}
	}
}

func TestSealDeepAndTrusted(t *testing.T) {
	b := newBarrier(t)
	p := &proto.Payload{
		V: 1, Seq: 9, SentAt: 1790000000, AgentVersion: "1.0.0", MachineFP: "0123456789abcdef",
		Host:    &proto.Host{Hostname: "web-01", OS: "Distro 8.8.8.8", Kernel: "6.8.0 1.2.3.4", Arch: "amd64"},
		Metrics: []proto.Metric{{TS: 1, Disks: []proto.Disk{{Mount: "/mnt/password=x", FS: "ext4"}}}},
		Events: []proto.Event{{
			ID: "01JABCD7XK4R2N5Q8V3W6Y9Z0E", TS: 1, Type: "service_failed", Severity: "P1", Count: 1,
			Key: "service_failed:from 8.8.4.4",
			Data: map[string]any{
				"unit":     "app.service",
				"pid":      json.Number("12345678901234567"),
				"nested":   map[string]any{"list": []any{"token=abc", 1.5, true, nil}},
				"log_tail": []any{"Failed password for root from 8.8.8.8 port 22"},
			},
			Snapshot: &proto.Snapshot{TopRSS: []proto.Process{{PID: 1, Comm: "mysqld", Cmdline: "mysqld -pRootPw2024"}}},
		}},
		Redactions: map[string]int{},
	}
	before, _ := json.Marshal(p)
	sp, err := b.Seal(p)
	if err != nil {
		t.Fatal(err)
	}
	after, _ := json.Marshal(p)
	if !bytes.Equal(before, after) {
		t.Fatal("Seal modified its input")
	}
	out := string(sp.Bytes())
	for _, leak := range []string{"8.8.4.4", "8.8.8.8 port", "token=abc", "RootPw2024", "password=x"} {
		if strings.Contains(out, leak) {
			t.Errorf("leak %q in %s", leak, out)
		}
	}
	// Trusted fields keep IP-like text; numbers stay exact.
	for _, keep := range []string{`"os":"Distro 8.8.8.8"`, `"kernel":"6.8.0 1.2.3.4"`, `"pid":12345678901234567`} {
		if !strings.Contains(out, keep) {
			t.Errorf("missing %s in %s", keep, out)
		}
	}
	var got proto.Payload
	_ = json.Unmarshal(sp.Bytes(), &got)
	want := map[string]int{"ipv4": 2, "kv_secret": 3, "cli_secret": 1}
	for k, v := range want {
		if got.Redactions[k] != v {
			t.Errorf("redactions = %v, want %v", got.Redactions, want)
			break
		}
	}
	if sp.Seq() != 9 || sp.Events() != 1 || sp.Metrics() != 1 {
		t.Errorf("metadata: seq=%d events=%d metrics=%d", sp.Seq(), sp.Events(), sp.Metrics())
	}

	// Restoring sealed bytes is byte-identical and does not inflate counts.
	r, err := b.Restore(sp.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(r.Bytes(), sp.Bytes()) {
		t.Fatalf("restore changed bytes\n%s\n%s", sp.Bytes(), r.Bytes())
	}
}

func TestHideHostname(t *testing.T) {
	b, err := New(Options{HideHostname: "web-01.example.com"})
	if err != nil {
		t.Fatal(err)
	}
	got := b.String("web-01.example.com: web-01 restarted, webby unaffected")
	if got != "host: host restarted, webby unaffected" {
		t.Fatalf("got %q", got)
	}
}

func TestEmailOptional(t *testing.T) {
	b, _ := New(Options{MaskEmail: false})
	if got := b.String("mail ops@example.com"); got != "mail ops@example.com" {
		t.Fatalf("got %q", got)
	}
}

func TestCustomPatterns(t *testing.T) {
	b, err := New(Options{ExtraPatterns: []string{`ACME-\d{6}`}})
	if err != nil {
		t.Fatal(err)
	}
	if got := b.String("order ACME-123456 shipped"); got != "order [REDACTED:custom] shipped" {
		t.Fatalf("got %q", got)
	}
	if _, err := New(Options{ExtraPatterns: []string{"("}}); err == nil {
		t.Fatal("want error for invalid pattern")
	}
}

func TestTruncatesLongStrings(t *testing.T) {
	b := newBarrier(t)
	s := strings.Repeat("é", 5000) // 10000 bytes
	if got := b.String(s); len(got) > maxString || !strings.HasPrefix(s, got) {
		t.Fatalf("len %d", len(got))
	}
}

func TestSplit(t *testing.T) {
	b := newBarrier(t)
	p := &proto.Payload{V: 1, Seq: 5, SentAt: 1, AgentVersion: "1", MachineFP: "0123456789abcdef",
		Metrics: []proto.Metric{{TS: 1}, {TS: 2}},
		Events:  []proto.Event{{ID: "01JABCD7XK4R2N5Q8V3W6Y9Z0E", Type: "oom_kill", Severity: "P1", Count: 1, Key: "k", Data: map[string]any{"x": "token=1"}}},
	}
	sp, _ := b.Seal(p)
	x, y, err := b.Split(sp)
	if err != nil {
		t.Fatal(err)
	}
	if x.Part() != 1 || y.Part() != 2 || x.Events() != 1 || y.Metrics() != 2 || x.Seq() != 5 || y.Seq() != 5 {
		t.Fatalf("split: %+v %+v", x, y)
	}
	if !strings.Contains(string(x.Bytes()), `"kv_secret":1`) || !strings.Contains(string(y.Bytes()), `"redactions":{}`) {
		t.Fatalf("counts: %s | %s", x.Bytes(), y.Bytes())
	}
	if _, _, err := b.Split(x); err == nil {
		t.Fatal("splitting a part must fail")
	}
}

// TestPerformance: a 100 KB payload seals in < 5 ms (spec A6.6).
func TestPerformance(t *testing.T) {
	if testing.Short() || raceEnabled {
		t.Skip("timing test")
	}
	b := newBarrier(t)
	p := bigPayload(100 << 10)
	_, _ = b.Seal(p) // warm up
	// CPU time of this OS thread, best of 3 rounds: immune to other
	// processes competing for the CPU (parallel packages, shared runners).
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	best := time.Hour
	for range 3 {
		start := threadCPU(t)
		const n = 10
		for range n {
			if _, err := b.Seal(p); err != nil {
				t.Fatal(err)
			}
		}
		best = min(best, (threadCPU(t)-start)/n)
	}
	if best > 5*time.Millisecond {
		t.Fatalf("seal of a 100 KB payload took %v CPU > 5ms", best)
	}
	t.Logf("seal of a 100 KB payload: %v CPU", best)
}

func threadCPU(t *testing.T) time.Duration {
	var ru syscall.Rusage
	if err := syscall.Getrusage(1 /* RUSAGE_THREAD */, &ru); err != nil {
		t.Skip("RUSAGE_THREAD unavailable:", err)
	}
	return time.Duration(ru.Utime.Nano() + ru.Stime.Nano())
}

func bigPayload(size int) *proto.Payload {
	lines := []any{}
	line := "Sep 25 10:01:02 web-01 sshd[1234]: Failed password for invalid user admin from 185.220.101.47 port 51514 ssh2"
	for n := 0; n < size; n += len(line) {
		lines = append(lines, line)
	}
	return &proto.Payload{V: 1, Seq: 1, SentAt: 1, AgentVersion: "1", MachineFP: "0123456789abcdef",
		Events: []proto.Event{{ID: "01JABCD7XK4R2N5Q8V3W6Y9Z0E", Type: "service_failed", Severity: "P1", Count: 1,
			Key: "k", Data: map[string]any{"log_tail": lines}}}}
}

func BenchmarkSeal100KB(b *testing.B) {
	br := newBarrier(b)
	p := bigPayload(100 << 10)
	for b.Loop() {
		if _, err := br.Seal(p); err != nil {
			b.Fatal(err)
		}
	}
}

func FuzzString(f *testing.F) {
	ins, _ := filepath.Glob("testdata/*.in")
	for _, in := range ins {
		raw, _ := os.ReadFile(in)
		for _, c := range strings.Split(string(raw), caseSep) {
			f.Add(c)
		}
	}
	b := newBarrier(f)
	f.Fuzz(func(t *testing.T, s string) {
		start := time.Now()
		out := b.String(s)
		if d := time.Since(start); d > 10*time.Millisecond && !raceEnabled {
			// Fuzz workers share the CPU; only fail if it is reproducibly slow.
			best := d
			for range 3 {
				start = time.Now()
				b.String(s)
				best = min(best, time.Since(start))
			}
			if best > 10*time.Millisecond {
				t.Fatalf("String took %v", best)
			}
		}
		if len(out) > maxString+len(s) { // markers can grow short matches a little
			t.Fatalf("output unexpectedly large: %d", len(out))
		}
	})
}
