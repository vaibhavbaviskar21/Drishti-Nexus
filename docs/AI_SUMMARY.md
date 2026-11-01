# AI Incident Summaries (Phase 5.1)

`drishti summarize` writes a short plain-English narrative for each incident in a
scan report, using a language model that runs **on the same machine**. It is:

- **Optional and off by default.** Nothing in `scan`, `analyze`, `tail` or `serve`
  calls a model. Detection stays deterministic; summaries are a separate step.
- **Clearly labeled.** Every summary, and the output file, carries
  `"AI-generated narrative — not evidence"`. Summaries are written to their own
  file and never change alerts, incidents or the scan report.
- **Grounded.** Every summary is checked against the incident facts by a
  deterministic checker (below). A summary with any unsupported claim is marked
  `"verified": false` and lists the claims under `unsupported_claims`.
- **Local only.** The endpoint must be a loopback address (`127.0.0.0/8`, `::1`,
  `localhost`). This is checked when the URL is parsed and again on every
  connection, so a `localhost` that resolves elsewhere, an `HTTP_PROXY`, or a
  redirect cannot send data off the machine. No new dependencies: plain
  `net/http` against the OpenAI-compatible `POST /chat/completions` API.

## Running it

1. Scan as usual (keep the log entries so evidence lines can be quoted):

   ```
   drishti scan testdata/fixtures/multihost -output scan.json
   ```

2. Start a local model server.

   llama.cpp:
   ```
   llama-server -m qwen2.5-7b-instruct-q4_k_m.gguf --host 127.0.0.1 --port 8080
   drishti summarize -in scan.json -out summaries.json
   ```

   Ollama (models must be pulled while online, then work offline):
   ```
   ollama serve
   drishti summarize -in scan.json -out summaries.json -endpoint http://127.0.0.1:11434/v1 -model qwen2.5:7b-instruct
   ```

Flags: `-in` (required), `-out` (default `summaries.json`), `-endpoint`
(default `http://127.0.0.1:8080/v1`), `-model` (default `local`; llama-server
ignores it, Ollama needs it), `-timeout` (per incident, default 5m). The output
refuses to overwrite the scan report or any evidence file listed in it.

## What the model receives

For each incident, one system message and one user message, with
`temperature: 0`. No tools, no follow-up queries.

- **System:** summarize only the given facts, no speculation about intent,
  attribution or impact; cite alert IDs; copy IPs, hosts, users, technique IDs,
  counts and times exactly; all times are UTC; 3–6 sentences.
- **User:** the incident as JSON: incident ID, first/last seen (UTC), and for
  each alert its ID, rule, severity, ATT&CK technique ID/name/tactic, first/last
  seen, count, description, details (user, src_ip, hosts, thresholds, …) and
  related alerts; plus up to 40 raw evidence lines the alerts cite (each cut at
  512 bytes; the number omitted is stated). An `-alerts-only` report has no
  evidence lines, so only alert facts are sent.

`prompt_sha256` in each summary is the SHA-256 of `system + "\n" + user`, and the
output file records the SHA-256 of the scan report it was built from, so a
narrative can be traced to its exact input.

## Grounding check

`ai.Check(summary, facts)` (in `internal/ai/ground.go`) is deterministic and does
not involve the model. The corpus is the exact JSON the model was shown.

1. **Extract claims** from the summary, in this order, blanking each match so its
   parts are not re-read (the digits of an IP are not counts):
   alert IDs (`ALERT-\d+`), incident IDs (`INC-\d+`), ATT&CK technique IDs
   (`T\d{4}(.\d{3})?`), timestamps (`YYYY-MM-DD[T ]HH:MM[:SS][zone]`), dates,
   times of day (`H:MM[:SS]`), IPv4 and IPv6 addresses (normalized, so
   `2001:DB8:0::1` equals `2001:db8::1`), names (the word after
   user/username/account/host/hostname/server/machine, a double-quoted or
   backticked token, or any token mixing letters and digits such as `web01`,
   `7m26s`, or a dotted name such as `mail.example.com`), and remaining integers.
2. **Support each claim** from the facts:
   - IDs, technique IDs, IPs: exact match with a value of the same kind in the
     facts (`10.0.0.1` does not match `10.0.0.11`).
   - Timestamps and times of day: inside the incident window (first seen to last
     seen of its alerts), at the precision written (a claim of `10:14` is
     compared by minute, `10:14:01` by second), or literally present in the facts.
     A bare time is checked on every day the window spans.
   - Dates: within the window's days.
   - Names: present, case-insensitively, in the facts' vocabulary.
   - Integers: present as a number in the facts (counts, thresholds, details,
     numbers in descriptions and evidence lines, digits of durations such as
     `7m26s`), or the number of alerts or evidence lines.
3. **Verified** means no unsupported claims.

### What it cannot catch

It checks concrete entities, not meaning. Known blind spots (pinned by
`TestGroundingKnownBlindSpots`):

- Speculation or paraphrased reasoning with no concrete entity:
  "the attacker then exfiltrated the database", "likely an insider".
- Numbers written as words ("eight attempts").
- A true value attached to the wrong thing: "6 failures from 10.0.0.11" passes
  when both 6 and 10.0.0.11 appear in the facts, even though they belong to
  different events. Any number that appears anywhere in the facts (including
  ports and PIDs in evidence lines) supports a count.
- Plain-word names without a cue: "Then bob logged in" is not extracted; "user
  bob" or `"bob"` is.
- Times are assumed UTC; a summary that converts to local time is flagged
  (fails safe).

It can also flag faithful text (also fails safe, never silently verifies):
identifier-like words absent from the facts, e.g. `IPv4` or `SHA-256`.

So `verified: true` means "no concrete claim contradicts the facts", not "the
narrative is correct". The narrative never replaces the alerts it cites.

## Evaluation

No model runtime is installed on the development machine, so the model itself
has **not** been evaluated: no measurement yet of how often a real 7–8B model
produces unsupported claims, or of analyst time saved. What is evaluated is the
checker, against the real pipeline output for two fixtures
(`testdata/fixtures/multihost`: 1 incident, 3 alerts — brute force then lateral
movement; `testdata/fixtures/sample_auth.log`: 4 incidents, 5 alerts).

`TestGroundingEvaluation` (`go test ./internal/ai -run Grounding -v`):

- One hand-written faithful narrative per incident, paraphrased the way an
  instruction-tuned model writes (times shortened to minutes, durations as
  "7 minutes 26 seconds", IDs cited inline). All must verify.
- Each faithful narrative is then extended with one planted hallucination per
  type, derived from that incident's facts so it is wrong for it specifically.

Result (2026-11-01):

| Case | Result |
|---|---|
| Faithful summaries verified (false-positive check) | 5/5 |
| Wrong IP address | caught 5/5 |
| Invented ATT&CK technique ID | caught 5/5 |
| Wrong count | caught 5/5 |
| Invented host ("host fileserver") | caught 5/5 |
| Invented host, identifier form ("app07") | caught 5/5 |
| Invented user (`"svc_backup"`) | caught 5/5 |
| Time of day outside the incident window | caught 5/5 |
| Full timestamp outside the window | caught 5/5 |
| Nonexistent alert ID | caught 5/5 |
| Wrong incident ID | caught 5/5 |

These rates are for planted, concrete hallucinations; they are an upper bound,
not a measure of real-model behavior. The next step is to run a local model over
the Phase 0 datasets and record how many summaries come back unverified, and
which unsupported claims were real errors versus checker false positives.

Other tests: `client_test.go` (request shape, temperature 0, HTTP errors,
non-JSON and empty replies, refused redirects, timeout, non-loopback endpoints
refused at parse and dial time); `TestCheckEdgeCases` (IPv6 normalization, IP
prefixes, a window spanning midnight); `internal/cli/summarize_test.go`
(scan report → summarize → labeled file, end to end against a stand-in server).
