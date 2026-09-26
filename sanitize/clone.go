package sanitize

import (
	"bytes"
	"encoding/json"
	"fmt"
	"maps"

	"github.com/xyfu/xnux-shared/proto"
)

// clonePayload deep-copies everything the barrier rewrites, so Seal never
// touches its input. Event data is normalized to the shapes JSON decoding
// produces (string, json.Number, bool, nil, []any, map[string]any): the walk
// only understands those, so nothing can hide in, say, a []string.
func clonePayload(p *proto.Payload) (*proto.Payload, error) {
	cp := *p
	if p.Host != nil {
		h := *p.Host
		h.Capabilities = append([]string(nil), p.Host.Capabilities...)
		cp.Host = &h
	}
	if p.Metrics != nil {
		cp.Metrics = make([]proto.Metric, len(p.Metrics))
		for i, m := range p.Metrics {
			m.Disks = append([]proto.Disk(nil), m.Disks...)
			m.Temps = append([]proto.Temp(nil), m.Temps...)
			cp.Metrics[i] = m
		}
	}
	if p.Events != nil {
		cp.Events = make([]proto.Event, len(p.Events))
		for i, e := range p.Events {
			if e.Data != nil {
				d, err := normalize(e.Data)
				if err != nil {
					return nil, fmt.Errorf("sanitize: event %s data: %w", e.ID, err)
				}
				e.Data = d.(map[string]any)
			}
			if e.Snapshot != nil {
				sn := *e.Snapshot
				sn.TopRSS = append([]proto.Process(nil), sn.TopRSS...)
				sn.TopCPU = append([]proto.Process(nil), sn.TopCPU...)
				e.Snapshot = &sn
			}
			cp.Events[i] = e
		}
	}
	if p.Diag != nil {
		d := *p.Diag
		d.CollectorErrors = maps.Clone(p.Diag.CollectorErrors)
		cp.Diag = &d
	}
	cp.Redactions = maps.Clone(p.Redactions)
	return &cp, nil
}

// normalize returns a deep copy of x in JSON-decoded shapes.
func normalize(x any) (any, error) {
	switch t := x.(type) {
	case nil, string, bool, json.Number:
		return t, nil
	case int:
		return json.Number(fmt.Sprint(t)), nil
	case int64:
		return json.Number(fmt.Sprint(t)), nil
	case uint64:
		return json.Number(fmt.Sprint(t)), nil
	case []string:
		out := make([]any, len(t))
		for i, v := range t {
			out[i] = v
		}
		return out, nil
	case []any:
		out := make([]any, len(t))
		for i, v := range t {
			n, err := normalize(v)
			if err != nil {
				return nil, err
			}
			out[i] = n
		}
		return out, nil
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, v := range t {
			n, err := normalize(v)
			if err != nil {
				return nil, err
			}
			out[k] = n
		}
		return out, nil
	default:
		// Anything else (floats, other ints, structs, typed slices) goes
		// through a JSON round trip.
		b, err := json.Marshal(t)
		if err != nil {
			return nil, err
		}
		dec := json.NewDecoder(bytes.NewReader(b))
		dec.UseNumber()
		var out any
		if err := dec.Decode(&out); err != nil {
			return nil, err
		}
		return out, nil
	}
}
