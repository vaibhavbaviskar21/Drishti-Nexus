# Web dashboard

## Launch

```
drishti serve [-port 8080] [-host 127.0.0.1] [-log <file>] [<file|dir> ...]
```

Files and directories (positional or `-log`) are run through the same pipeline as
`scan`: hashed, opened read-only, parsed, detected, audited. Passing several hosts'
logs (e.g. `drishti serve testdata/fixtures/multihost`) correlates them into shared
incidents. The server binds to `127.0.0.1` unless `-host` says otherwise. Open
`http://127.0.0.1:8080`.

## Views

| Tab | Shows |
|---|---|
| Overview | KPI tiles (lines read, parsed entries, alerts, incidents, clean-parse %), alerts by severity, alerts by rule, top sources, latest incidents |
| Incidents | Alerts grouped by incident ID, latest activity first, with max severity, hosts and ATT&CK techniques. Expanding one shows its alert timeline (first/last seen, rule, severity, match count, description) and linked alerts |
| Alerts | Filterable table (text search, severity, rule, host) with CSV/JSON export of the filtered rows. A row (click or Enter) opens a drawer with the details map, ATT&CK technique (plain link to attack.mitre.org), linked alerts and the cited evidence lines resolved to raw log text |
| Log stream | Recent entries, newest first, refreshed over the WebSocket and every 15 s; Pause/Resume and a line filter |
| Chain of custody | Audit session ID, command, tool/Go version, evidence files with SHA-256 before/after and integrity status, effective rule configuration |

Dark mode follows the OS setting; the moon button overrides it and is remembered in
`localStorage`. Tabs use arrow keys/Home/End, the drawer closes with Esc and returns
focus to the row that opened it.

## JSON endpoints

| Endpoint | Returns |
|---|---|
| `GET /api/stats` | counts, parse quality, severity/rule/source breakdowns |
| `GET /api/alerts` | all alerts, newest first |
| `GET /api/alerts/{id}` | one alert plus `evidence` (cited lines with `raw_log`, `found=false` if evicted from memory) and `hosts`; 404 if unknown |
| `GET /api/incidents` | incidents with chronological `alerts`; `[]` when none |
| `GET /api/session` | the `audit.Session` for the loaded evidence; `null` when nothing was loaded |
| `GET /api/logs` | the 200 most recent entries |
| `/api/ws` | WebSocket; same-origin only |

## Security

- Every response carries `Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self'; ... frame-ancestors 'none'`,
  `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`, `Cache-Control: no-store`.
  No inline script, handlers or style attributes (enforced by `TestIndexAndAssetsServed`).
- Log content is attacker-controlled: the JavaScript builds the DOM with `createElement`/`textContent` only, never `innerHTML`.
  ATT&CK links are built only from IDs matching `T####(.###)`. CSV export prefixes cells starting with `= + - @` to block formula injection.

## Offline guarantees

HTML, CSS and JS are embedded in the binary (`go:embed`); system fonts only; no CDN,
external font, analytics or network call. The only external URL is the optional
ATT&CK reference link, opened only if the analyst clicks it.
