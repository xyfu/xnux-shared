# xnux-shared

Code shared by the [Xnux](https://xnux.net) agent and service. Apache-2.0.

| Package | Contents |
| --- | --- |
| [`proto`](proto) | The v1 ingest payload: Go types, the event type registry (category, object, end condition; [registry.go](proto/registry.go)), the normative JSON Schema ([ingest.v1.schema.json](proto/ingest.v1.schema.json)) and the redaction-marker regexes ([redaction_markers.json](proto/redaction_markers.json)) |
| [`health`](health) | Server health score 0–100 (`health/v2`): rules, hard caps and the explanation of every deduction; the service and the agent's CLI share it |
| [`sanitize`](sanitize) | The redaction barrier every outgoing payload passes through, with its golden test corpus ([sanitize/testdata](sanitize/testdata)) |

The agent lives in [xyfu/xnux-agent](https://github.com/xyfu/xnux-agent).

```sh
go test -race ./...
go test ./sanitize -run '^$' -fuzz FuzzString -fuzztime 60s
```
