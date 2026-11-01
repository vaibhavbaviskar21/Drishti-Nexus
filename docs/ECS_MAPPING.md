# ECS Normalization (Phase 2.6)

Drishti Nexus normalizes every parsed log entry onto [Elastic Common Schema (ECS)](https://www.elastic.co/guide/en/ecs/current/index.html) **8.11**, the common event taxonomy used for SIEM and data-lake export. This is the "universal schema" in the NTRO Universal Log Pre-processing Framework brief.

```bash
drishti scan -ecs events.ndjson logs/          # one ECS JSON document per line
```

The export is **streamed** while files are parsed. It is not capped by `max_log_entries`, and it covers every entry, not only those that raised alerts. The file is hashed into the audit trail like every other output, and it is refused if it would overwrite evidence.

The mapping lives in one place: [`internal/ecs/ecs.go`](../internal/ecs/ecs.go). Parsers keep their own field names, because detection rules key on them. ECS is the output view.

## Preservation and traceability (NTRO a, d)

Every document carries the original record and a path back to the exact evidence line:

| Field | Content |
|---|---|
| `event.original` | The raw line exactly as read (after BOM/encoding repair, flagged in `drishti.fields`) |
| `event.id` | `<file label>:<line>`, the same ID alerts cite in `related_logs` |
| `log.file.path` | Evidence file path |
| `drishti.evidence_sha256` | SHA-256 of that file, taken before analysis and re-verified after |
| `drishti.session_id` | Audit-log session that produced the document |
| `drishti.line` | First physical line of the entry (multi-line entries span several) |
| `drishti.parser`, `drishti.parse_quality` | Which parser produced it; `Clean` / `Partial` / `BestEffort` |
| `drishti.fields` | Every parsed attribute with no ECS home, under its original name. Nothing parsed is dropped |

`drishti.*` is the custom namespace for tool-specific fields, as ECS recommends.

## Field mapping (NTRO b, c)

| Source | Parser field | ECS field |
|---|---|---|
| all | timestamp (UTC) | `@timestamp` |
| all | message | `message` |
| all | severity | `log.level` |
| all | host | `host.name` (omitted when the log names no host) |
| auth (sshd, PAM, Windows logon) | `auth_result` failure/success | `event.category: [authentication]`, `event.outcome` |
| auth | `auth_event` | `event.action` |
| auth | `user` | `user.name` |
| auth | `src_ip`, `src_port` | `source.ip`, `source.port` |
| syslog | `program`, `pid` | `process.name`, `process.pid` |
| syslog (`<PRI>`) | `priority` | `log.syslog.priority` |
| RFC 5424 | `app_name`, `proc_id`, `msg_id`, `structured_data` | `log.syslog.appname`, `.procid`, `.msgid`, `.structured_data` |
| Apache/Nginx | `src_ip` (client) | `source.ip` (the access log names no server, so no `host.name`) |
| Apache/Nginx | `method`, `path`, `protocol` | `http.request.method`, `url.original`, `http.version` |
| Apache/Nginx | `status`, `size` | `http.response.status_code`, `http.response.body.bytes` |
| Apache/Nginx | `referer`, `user_agent` | `http.request.referrer`, `user_agent.original` |
| Windows JSON (EVTX exports) | `EventID` | `winlog.event_id`, `event.code` |
| Windows JSON | `Channel` | `winlog.channel` |
| Windows JSON | `Image`, `CommandLine`, `ProcessId` | `process.executable`, `process.command_line`, `process.pid` |
| Windows JSON | `ParentImage`, `ParentCommandLine` | `process.parent.executable`, `process.parent.command_line` |
| Windows JSON | `ScriptBlockText` | `powershell.file.script_block_text` |
| Windows JSON | `TargetUserName`, `IpAddress` (logon events) | `user.name`, `source.ip` |
| CEF / LEEF header | vendor, product, version | `observer.vendor`, `observer.product`, `observer.version` |
| CEF / LEEF header | signature ID / EventID | `event.code` |
| CEF / LEEF | severity (0-10) | `event.severity` (CEF:1 words such as `Very-High` stay in `drishti.fields`) |
| CEF `src`/`spt`/`dst`/`dpt`, LEEF `src`/`srcPort`/`dst`/`dstPort` | `src_ip`, `src_port`, `dst_ip`, `dst_port` | `source.*`, `destination.*` |
| CEF `duser` (else `suser`), LEEF `usrName` (else `accountName`) | `user` | `user.name` |
| CEF / LEEF | every extension attribute, unmodified | `drishti.fields.cef.*` / `drishti.fields.leef.*` |

### CEF and LEEF input

- **CEF** (ArcSight, versions 0 and 1) and **LEEF** (QRadar, 1.0 and 2.0) are parsed bare or inside any syslog envelope (BSD, RFC 5424, ISO). The envelope gives the relay host and time, and the payload gives the device fields.
- **Time:** the device's own event time (CEF `rt`, LEEF `devTime`) wins over the envelope time, as the LEEF spec requires. Accepted forms are epoch seconds or milliseconds (10 or 13 digits), `Jan 02 2006 15:04:05[ -0700]`, and ISO 8601. LEEF `devTimeFormat` (a Java date pattern) is not interpreted. A `devTime` in another layout is kept as `device_time_unparsed` and the entry is marked `Partial`, never guessed.
- **CEF escaping:** `\|` and `\\` in the header; `\=`, `\\`, `\n`, `\r` in extension values. Values may contain spaces. An unescaped `=` inside a value, as in URLs or base64, stays part of the value unless the word before it is a valid key.
- **LEEF delimiter:** tab by default. LEEF 2.0 takes a single character or hex (`x5E`, `0x09`).
- **Authentication:** an event whose name, class or category mentions login, logon or auth is classified as failure or success from its `outcome` or `cat`. Vendor logins then feed the brute-force and lateral-movement rules like sshd logins do.
### CSV and Windows Event XML input

- **CSV** files are recognised by their **first line** being a header: 3 or more name-like columns, one of them a time column (`timestamp`, `time`, `date`, `Date and Time`, `CreationDate`, `TimeGenerated`, …). Ordinary log lines that happen to contain commas never switch a file to CSV. Each row is keyed by the header and goes through the same extraction as JSON (time, host, message, severity, Windows logons). Quoted fields may span lines, as in Event Viewer descriptions, and `""` escapes are honoured. A row with the wrong number of fields is kept as `BestEffort`, not dropped.
  - **Split timestamps** are joined: `Date`+`Time` (`2016-09-28` `04:30:30`), or month/day/time without a year (`Dec` `10` `06:55:46`, year inferred as for syslog).
  - **Column names** matching the detection fields case-insensitively (`Pid`, `User`, `Program`, `src_ip`) are used for them. LogHub's structured CSV of the 2k OpenSSH sample therefore raises exactly the same alerts as the raw log (`TestIntegration_CSVMatchesRawSyslog`).
  - Locale-dependent dates such as Event Viewer's `10/31/2026 2:14:03 PM` are **not** guessed. They leave the time missing (flagged) rather than risk swapping day and month.
- **Windows Event XML** (`<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">`), one event per record, single- or multi-line, as written by `wevtutil qe /f:xml` or `Get-WinEvent … ToXml()`. `<?xml?>` and `<Events>` wrapper lines are skipped. The event becomes the Windows-export key names (`EventID`, `Computer`, `Channel`, `ProviderName`, each `<Data Name="…">`), so 4624/4625 logon classification and the ECS mapping apply as for JSON exports. Windows levels map 1 to critical, 2 to error, 3 to warning, and 4/0 to info. Without `RenderingInfo`, the message is built from the event data (`message_synthesized`), so content rules still see command lines.
  - Not supported yet: several `<Event>` elements on one physical line (Event Viewer "Save as XML" writes one UTF-16 `<Events>` line). Re-export with `wevtutil qe <log> /f:xml`, which writes one event per line.
- **Tests:** [`internal/parser/csvxml_test.go`](../internal/parser/csvxml_test.go) and [`internal/pipeline/formats_test.go`](../internal/pipeline/formats_test.go) use real samples: LogHub's structured CSVs (OpenSSH 2k, and the first 200 Windows rows) and Microsoft's documented 4625 event XML.

- **CEF/LEEF tests:** [`internal/parser/cef_test.go`](../internal/parser/cef_test.go) runs the edge cases from the Apache-2.0 [logstash-codec-cef](https://github.com/logstash-plugins/logstash-codec-cef) test suite, plus the examples in the ArcSight CEF and IBM LEEF specifications.

Numeric fields are written as numbers. A value that isn't one (Apache size `-`) stays in `drishti.fields` instead of being forced.

## Example

Input line:
```
2025-03-10T10:14:01+00:00 web01 sshd[2101]: Failed password for deploy from 203.0.113.50 port 51120 ssh2
```
Output document (pretty-printed; the file has one per line):
```json
{
  "@timestamp": "2025-03-10T10:14:01Z",
  "ecs": {"version": "8.11.0"},
  "event": {"kind": "event", "id": "logs/web01/auth.log:3", "category": ["authentication"],
            "outcome": "failure", "action": "password_failed",
            "original": "2025-03-10T10:14:01+00:00 web01 sshd[2101]: Failed password for deploy from 203.0.113.50 port 51120 ssh2"},
  "host": {"name": "web01"},
  "user": {"name": "deploy"},
  "source": {"ip": "203.0.113.50", "port": 51120},
  "process": {"name": "sshd", "pid": 2101},
  "log": {"level": "info", "file": {"path": "logs/web01/auth.log"}},
  "message": "Failed password for deploy from 203.0.113.50 port 51120 ssh2",
  "drishti": {"parser": "syslog", "parse_quality": "Clean", "line": 3, "facility": "sshd",
              "session_id": "…", "evidence_sha256": "…",
              "fields": {"auth_count": 1, "tag": "sshd", "timestamp_raw": "2025-03-10T10:14:01+00:00", "tz_offset": "+00:00"}}
}
```

## Not yet covered

- **YAML-defined parsers** for new sources: the next 2.6 step.
- **Windows field coverage** is the common Security/Sysmon/PowerShell set listed above. Other EVTX fields are kept under their original names in `drishti.fields`.
- **`event.category` for non-auth events** (process, network, file) is not inferred yet.
- **Size.** For JSON input, `event.original` and `drishti.fields` both carry the source attributes, roughly doubling document size. This is a deliberate trade for losslessness; it can be revisited if export volume becomes the bottleneck.
