package health

import (
	"fmt"
	"strings"
)

type phrase struct{ zh, en string }

// Phrases take the value (%[1]v, rounded) and the subject (%[2]s). Wording
// follows xnux-pm specs/06 (unified terms): English counts read "label:
// n" (no plural forms to get wrong), °C everywhere.
var phrases = map[string]phrase{
	"open_service_failed":   {"%[2]s 处于失败状态", "%[2]s is in a failed state"},
	"open_service_failed#":  {"处于失败状态的服务：%[1]v 个", "Services in a failed state: %[1]v"},
	"oom_24h":               {"24 小时内内存耗尽 %[1]v 次", "Out-of-memory kills in 24 h: %[1]v"},
	"service_crashes_24h":   {"24 小时内服务崩溃 %[1]v 次", "Service crashes in 24 h: %[1]v"},
	"segfaults_24h":         {"24 小时内段错误 %[1]v 次", "Segfaults in 24 h: %[1]v"},
	"cpu_p95":               {"CPU 使用率 %[1]v%%（1 小时 P95）", "CPU usage %[1]v%% (1-hour P95)"},
	"mem_avail_p5":          {"可用内存低至 %[1]v%%", "Available memory down to %[1]v%%"},
	"swap_in_p95":           {"Swap 换入 %[1]v 页/秒", "Swapping in %[1]v pages/s"},
	"iowait_p95":            {"iowait %[1]v%%（1 小时 P95）", "iowait %[1]v%% (1-hour P95)"},
	"load_per_core_p95":     {"每核负载 %[1]v", "Load per core %[1]v"},
	"disk_days_to_full":     {"%[2]s 约 %[1]v 天后写满", "%[2]s will be full in about %[1]v days"},
	"disk_used_pct":         {"%[2]s 已用 %[1]v%%", "%[2]s %[1]v%% used"},
	"inode_used_pct":        {"%[2]s inode 已用 %[1]v%%", "%[2]s inodes %[1]v%% used"},
	"open_p1_security":      {"%[1]v 个未结束的 P1 安全事件", "Unresolved P1 security events: %[1]v"},
	"open_p2_security":      {"%[1]v 个未结束的 P2 安全事件", "Unresolved P2 security events: %[1]v"},
	"root_password_login":   {"24 小时内 root 用密码登录过", "root logged in with a password in the last 24 h"},
	"open_ssh_attack":       {"允许密码登录，正在被暴力破解", "Password login is on and under brute-force attack"},
	"open_ssh_attack_root":  {"root 允许用密码登录，正在被暴力破解", "root can log in with a password and is under brute-force attack"},
	"open_db_public_access": {"数据库正被公网访问", "A database is being accessed from the internet"},
	"temp_p95":              {"温度 %[1]v°C（1 小时 P95）", "Temperature %[1]v°C (1-hour P95)"},
	"hung_task_24h":         {"24 小时内进程阻塞 %[1]v 次", "Hung tasks in 24 h: %[1]v"},
	"open_p0_intrusion":     {"有未结束的入侵事件", "An intrusion event is unresolved"},
	"open_docker_api":       {"Docker API 正暴露在公网", "The Docker API is exposed to the internet"},
	"open_disk_failure":     {"磁盘错误或文件系统只读", "Disk errors or a read-only file system"},
	"disk_full_imminent":    {"磁盘即将写满", "A disk is about to fill up"},
	"oom_memory_exhausted":  {"刚发生内存耗尽且内存仍不足", "Memory just ran out and is still short"},
	"agent_outdated":        {"探针版本较旧，建议更新", "The agent is outdated; consider updating it"},
}

// names are the items without a value: what an accepted item ("don't
// remind me", delta 13.6) is about. %[1]s is the subject.
var names = map[string]phrase{
	"open_service_failed":   {"%[1]s 处于失败状态", "%[1]s in a failed state"},
	"oom_24h":               {"24 小时内内存耗尽", "Out-of-memory kills in 24 h"},
	"service_crashes_24h":   {"24 小时内服务崩溃", "Service crashes in 24 h"},
	"segfaults_24h":         {"24 小时内段错误", "Segfaults in 24 h"},
	"cpu_p95":               {"CPU 使用率", "CPU usage"},
	"mem_avail_p5":          {"可用内存", "Available memory"},
	"swap_in_p95":           {"Swap 换入", "Swapping in"},
	"iowait_p95":            {"iowait", "iowait"},
	"load_per_core_p95":     {"每核负载", "Load per core"},
	"disk_days_to_full":     {"%[1]s 预计写满时间", "Time until %[1]s is full"},
	"disk_used_pct":         {"%[1]s 磁盘用量", "%[1]s disk usage"},
	"inode_used_pct":        {"%[1]s inode 用量", "%[1]s inode usage"},
	"temp_p95":              {"温度", "Temperature"},
	"hung_task_24h":         {"24 小时内进程阻塞", "Hung tasks in 24 h"},
	"open_db_public_access": {"数据库被公网访问", "Database accessed from the internet"},
}

// Name renders an item without its value, for the accepted list; the
// subject is left out when there is none ("all mounts").
func Name(item, subject, lang string) string {
	p, ok := names[item]
	if !ok {
		return Describe(item, 0, subject, lang)
	}
	f := pick(p, lang)
	if !strings.Contains(f, "%[") {
		return f
	}
	if subject == "" {
		return strings.TrimSpace(strings.Replace(f, "%[1]s", "", 1))
	}
	return fmt.Sprintf(f, subject)
}

// pick is the phrase in lang: Chinese for zh*, English for anything else
// (spec v1.1 delta 11.2, the same fallback as the service's).
func pick(p phrase, lang string) string {
	if strings.HasPrefix(strings.ToLower(lang), "zh") {
		return p.zh
	}
	return p.en
}

// Describe renders an item (a deduction, a cap or a suggestion) as one
// line in lang (zh* or anything else for English).
func Describe(item string, value float64, subject, lang string) string {
	p, ok := phrases[item]
	if q, ok2 := phrases[item+"#"]; ok2 && subject == "" {
		p, ok = q, true // without a subject (results of earlier versions)
	}
	if !ok {
		return item
	}
	f := pick(p, lang)
	if !strings.Contains(f, "%[") {
		return f // no placeholders: Sprintf would append %!(EXTRA …)
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
