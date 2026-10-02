package proto

// Split divides a payload in two for size limits: events (with host, diag,
// the security summary and the failed units) go first and metrics second;
// a payload holding only one kind is halved. Both halves keep the header
// fields and redaction counts; ok is false when p cannot be split further.
// Callers set Part.
func Split(p *Payload) (a, b *Payload, ok bool) {
	hdr := func() *Payload {
		return &Payload{V: p.V, Seq: p.Seq, Part: p.Part, SentAt: p.SentAt, AgentVersion: p.AgentVersion,
			MachineFP: p.MachineFP, Redactions: copyCounts(p.Redactions)}
	}
	a, b = hdr(), hdr()
	a.Host, a.Diag, a.SecuritySummary, a.ServicesFailed = p.Host, p.Diag, p.SecuritySummary, p.ServicesFailed
	switch {
	case len(p.Events) > 0 && len(p.Metrics) > 0:
		a.Events, b.Metrics = p.Events, p.Metrics
	case len(p.Events) > 1:
		h := len(p.Events) / 2
		a.Events, b.Events = p.Events[:h], p.Events[h:]
	case len(p.Metrics) > 1:
		h := len(p.Metrics) / 2
		a.Metrics, b.Metrics = p.Metrics[:h], p.Metrics[h:]
	default:
		return nil, nil, false
	}
	return a, b, true
}

func copyCounts(m map[string]int) map[string]int {
	out := make(map[string]int, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}
