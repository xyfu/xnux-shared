package health

import (
	"fmt"
	"strings"
)

type phrase struct{ zh, en string }

// Phrases take the value (%[1]v, rounded) and the subject (%[2]s).
var phrases = map[string]phrase{
	"open_service_failed":  {"%[1]v 个服务处于失败状态", "%[1]v service(s) in a failed state"},
	"oom_24h":              {"24 小时内 OOM %[1]v 次", "%[1]v OOM kill(s) in 24 h"},
	"service_crashes_24h":  {"24 小时内服务崩溃 %[1]v 次", "%[1]v service crash(es) in 24 h"},
	"segfaults_24h":        {"24 小时内段错误 %[1]v 次", "%[1]v segfault(s) in 24 h"},
	"cpu_p95":              {"CPU P95 %[1]v%%", "CPU P95 %[1]v%%"},
	"mem_avail_p5":         {"可用内存低至 %[1]v%%", "available memory down to %[1]v%%"},
	"swap_in_p95":          {"Swap 换入 %[1]v 页/秒", "swapping in %[1]v pages/s"},
	"iowait_p95":           {"iowait P95 %[1]v%%", "iowait P95 %[1]v%%"},
	"load_per_core_p95":    {"每核负载 %[1]v", "load per core %[1]v"},
	"disk_days_to_full":    {"%[2]s 约 %[1]v 天后写满", "%[2]s full in about %[1]v days"},
	"disk_used_pct":        {"%[2]s 已用 %[1]v%%", "%[2]s %[1]v%% used"},
	"inode_used_pct":       {"%[2]s inode 已用 %[1]v%%", "%[2]s inodes %[1]v%% used"},
	"open_p1_security":     {"%[1]v 个未处理的 P1 安全事件", "%[1]v open P1 security event(s)"},
	"open_p2_security":     {"%[1]v 个未处理的 P2 安全事件", "%[1]v open P2 security event(s)"},
	"root_password_login":  {"root 可用密码登录", "root can log in with a password"},
	"temp_p95":             {"温度 P95 %[1]v℃", "temperature P95 %[1]v°C"},
	"hung_task_24h":        {"24 小时内 hung_task %[1]v 次", "%[1]v hung task(s) in 24 h"},
	"open_p0_intrusion":    {"存在未处理的入侵事件", "an intrusion event is open"},
	"open_disk_failure":    {"磁盘错误或文件系统只读", "disk errors or a read-only file system"},
	"disk_full_imminent":   {"磁盘即将写满", "a disk is about to fill up"},
	"oom_memory_exhausted": {"刚发生 OOM 且内存仍不足", "OOM just happened and memory is still short"},
	"agent_outdated":       {"探针版本较旧，建议升级", "the agent is outdated; consider upgrading"},
}

// Describe renders an item (a deduction, a cap or a suggestion) as one
// line in lang ("zh-CN" or "en").
func Describe(item string, value float64, subject, lang string) string {
	p, ok := phrases[item]
	if !ok {
		return item
	}
	f := p.zh
	if strings.HasPrefix(lang, "en") {
		f = p.en
	}
	if subject == "" {
		subject = "/"
	}
	return fmt.Sprintf(f, trim(value), subject)
}

// trim prints 3 as "3" and 3.14 as "3.1".
func trim(v float64) string {
	s := fmt.Sprintf("%.1f", v)
	return strings.TrimSuffix(s, ".0")
}
