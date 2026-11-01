# Drishti Nexus — Phase-Wise Implementation Plan
### Goal: Turn Drishti Nexus into a tool real IR/SOC practitioners would actually run, not a demo

---

## Guiding Principles (apply to every phase)

1. **Evidence over features.** Every phase ends with a measurable artifact (a benchmark, a false-positive rate, a test corpus result) — not just "added X."
2. **Don't modify source logs, ever.** Chain-of-custody integrity is non-negotiable for anything IR-adjacent.
3. **Prefer boring and correct over novel and fragile.** Deterministic rules, tested parsers, and honest limitations beat AI narrative layers on a shaky foundation.
4. **Real data, early.** Public IR datasets go into the test suite in Phase 1, not Phase 4.
5. **Air-gapped-first stays the core identity.** Distributed mode, cloud telemetry, and license servers are optional bolt-ons for later — never let them compromise the offline story.

---

## Phase 0 — Baseline & Instrumentation (3–5 days)

Before changing anything, establish what "better" means.

### Tasks
- [ ] Stand up a benchmark harness: a script that runs `drishti scan` against a folder of log files and outputs a structured JSON summary (parse errors, alerts per rule, processing time, memory used).
- [ ] Collect 4–6 public log datasets for testing:
  - Splunk **Boss of the SOC (BOTS)** dataset (v1/v2/v3) — real-world-style Windows/Linux/network logs with known ground-truth incidents.
  - **DFIR public case sample sets** (e.g., DFIR Report sample data, AttackIQ / Mordor datasets).
  - **EVTX-ATTACK-SAMPLES** (GitHub, `sbousseaden/EVTX-ATTACK-SAMPLES`) for Windows event log coverage.
  - A week of "boring" production-like logs (auth.log, syslog from a real or realistic environment) to measure false positives on **benign** traffic — this matters as much as detecting attacks.
- [ ] Record baseline metrics on current build: parse success rate, crash/exception count, alert count per rule, false positive rate on benign set (manually reviewed sample).
- [ ] Set up `go test` + `golangci-lint` + `gosec` in CI now, even before the CI/CD phase — cheap and catches regressions from day one.

### Deliverable
A `BASELINE.md` with hard numbers: "X% of BOTS v3 auth logs parsed correctly, Y false positives per 1,000 benign log lines, current privilege-escalation rule fires on Z% of legitimate sudo usage."

This document becomes your report card for every subsequent phase.

---

## Phase 1 — Harden the Foundation (2–4 weeks)

Fix what breaks on real data before adding anything new.

### 1.1 Parser Robustness
- [ ] Feed all Phase 0 datasets through the parser; catalog every parse failure and malformed-line case.
- [ ] Handle mixed encodings (UTF-8 BOM, Latin-1 fallback), truncated lines, embedded newlines in JSON logs, and multi-line stack-trace-style entries.
- [ ] Handle clock skew / timezone inconsistency across hosts — normalize to UTC internally, retain original offset in `Fields`.
- [ ] Handle DST transition edge cases in timestamp parsing (a known source of silent bugs in time-window rules).
- [ ] Add a "confidence" or "parse quality" flag per entry so downstream rules/UI can distinguish clean vs. best-effort parses.

### 1.2 Chain of Custody & Audit Trail
- [ ] On ingest, compute and store a SHA-256 hash of every source file, logged with timestamp and tool version.
- [ ] Add an append-only audit log (`audit.log` or embedded in exports) recording: which rules ran, with what config/thresholds, on which files, when, and who (OS user) ran it.
- [ ] Guarantee read-only access to source files (verify no code path opens logs in write mode).
- [ ] Include the file hash and audit trail in every exported report (JSON/CSV) so results can be cited as evidence.

### 1.3 Alert Deduplication & Correlation (basic)
- [ ] Prevent the same underlying event sequence from triggering both "Brute Force" and "Excessive Failures" as two unrelated alerts — link them as related or suppress the redundant lower-severity one.
- [ ] Add an `IncidentID` or `GroupID` field so alerts from the same source/timeframe can be visually and programmatically grouped.

### 1.4 Persistence (optional backend)
- [ ] Add SQLite as an **optional** storage backend behind the existing storage interface (keep in-memory as default for speed).
- [ ] On crash/restart, allow resuming from the last persisted state instead of losing everything — critical for long `tail` sessions during live incident response.

### 1.5 Testing
- [ ] Unit tests per parser (format detection edge cases).
- [ ] Unit tests per detection rule, including deliberate "just under threshold" adversarial cases (e.g., 2 failures in 6 minutes should NOT alert; verify the boundary is exact).
- [ ] Integration test: full pipeline against each Phase 0 dataset, asserting expected alert counts stay within a known range (regression protection).

### Deliverable
- Updated `BASELINE.md` numbers showing measurable improvement in parse success rate and reduced false positives.
- A `CHAIN_OF_CUSTODY.md` describing the hashing/audit design.
- CI pipeline green on lint + tests + gosec.

---

## Phase 2 — Detection That Actually Differentiates (3–5 weeks)

This is the highest-leverage phase. Do this before any AI work.

### 2.1 Adaptive Thresholds (no ML required)
- [ ] Replace hardcoded thresholds with rolling per-source statistics (simple mean/stddev of failure rate over a trailing window) so "3 failures in 5 minutes" becomes relative to that source's normal baseline rather than a fixed global number.
- [ ] Keep the static threshold as a fallback/floor (e.g., never require fewer than 2) so behavior stays explainable and auditable — avoid becoming an unexplainable black box.

### 2.2 Multi-Source / Multi-Host Correlation
- [ ] Extend `scan`/`analyze` to accept multiple log files or a directory, tagging entries with their source host.
- [ ] Build cross-host correlation: e.g., brute force on Host A followed by a new session with the same account on Host B within N minutes → a single higher-severity "lateral movement candidate" incident.
- [ ] This is likely your single biggest real-world differentiator — most lightweight tools only look at one file at a time.

### 2.3 MITRE ATT&CK Mapping
- [ ] Tag each existing rule with its corresponding ATT&CK technique ID (e.g., Brute Force → T1110, Privilege Escalation → T1548/T1068, Suspicious Commands → T1059, Injection → T1190, Time Anomaly → contextual/T1078 possibly).
- [ ] Include the technique ID and tactic name in the `Alert` struct and in exported reports.
- [ ] This is a small engineering lift with outsized credibility payoff — analysts and their reports run on ATT&CK terminology.

### 2.4 Sigma Rule Support
- [ ] Integrate a Go Sigma rule engine (evaluate existing libraries first; build a minimal evaluator if none fit the offline/single-binary constraint).
- [ ] Support loading a folder of community Sigma rules from disk (USB-updatable, consistent with your offline philosophy).
- [ ] Map Sigma's field/log-source taxonomy to your normalized `LogEntry` model — this mapping layer is the real engineering work, not the parser itself.
- [ ] Keep your 6 native rules as "core" fast-path rules; Sigma becomes the extensible layer.

### 2.6 Universal Schema & Ingestion (added 2026-10-31 for the NTRO "Universal Log Pre-processing Framework" brief)
Do this before 2.4: the Sigma field-mapping layer and the NTRO common taxonomy are the same work.
- [x] Normalize every parser's output onto Elastic Common Schema (ECS) field names, keeping `raw_log` and the `file:line` ID so every normalized event traces back to its original (NTRO a, c, d).
- [x] Add CEF, LEEF, CSV and XML parsers, each tested against real samples (NTRO b). *(XML = Windows Event XML; see docs/ECS_MAPPING.md for scope.)*
- [ ] Declarative YAML parser definitions loaded from disk, so a new source needs no Go code (NTRO e, i).
- [x] ECS NDJSON export for SIEM/data-lake ingestion (NTRO g, h).
- [ ] Measure and publish sustained throughput in `BASELINE.md` instead of building distributed mode (NTRO "billions of events/day").
- [ ] Dockerfile wrapping the single binary (NTRO k). Pulled forward from Phase 6 by explicit approval; the air-gapped binary stays the flagship.

Execution order for Phase 2 (agreed 2026-10-31): 2.3 → 2.2 → 2.6 → 2.1 → 2.5 → 2.4.

### 2.5 False Positive Tuning
- [ ] Re-run the Phase 0 benign dataset against the updated engine; measure and publish the new FP rate per rule.
- [ ] Specifically address Privilege Escalation (broad keyword match) — consider requiring correlation with an anomaly (e.g., off-hours, or a user who doesn't normally use sudo) before elevating severity, rather than flat keyword matching.

### Deliverable
- Updated `BASELINE.md` with FP rate improvement numbers.
- `ATTACK_MAPPING.md` listing every rule → technique ID.
- Multi-host correlation demo against a BOTS dataset showing a linked incident timeline.

---

## Phase 3 — Reporting & Interoperability (2–3 weeks)

Make results usable outside the tool itself.

### 3.1 Incident Reports
- [ ] Generate a clean HTML report per scan: summary stats, grouped incidents (from Phase 2.2), ATT&CK tags, chain-of-custody hashes, audit trail.
- [ ] Add a PDF export path (render HTML to PDF, or generate directly) — analysts attach these to case files.

### 3.2 Export Formats (build only if there's real demand)
- [ ] CEF/LEEF export for SIEM ingestion — treat as a "nice to have," not a Phase 3 requirement, unless a specific user/client asks.
- [ ] Keep JSON/CSV export (already exists) as the default machine-readable format.

### 3.3 Compliance Mapping (optional, only if targeting regulated environments)
- [ ] Map relevant rules to HIPAA/PCI-DSS/ISO 27001 control references in report templates — low effort, mostly documentation, useful for specific buyer segments. Don't over-invest here unless you have a target customer asking for it.

### Deliverable
Sample HTML/PDF incident report generated from a Phase 0 dataset, good enough to hand to a real analyst for feedback.

---

## Phase 4 — Real-World Validation (ongoing, start ASAP in parallel with Phase 2/3)

This phase should start *before* Phase 2 finishes, not after.

### Tasks
- [ ] Post the tool (with a public dataset attached, e.g., a BOTS subset) in DFIR-focused communities: r/DFIR, r/netsec, SANS/DFIR Discord, Velociraptor/Wazuh community forums.
- [ ] Directly recruit 3–5 practitioners (IR consultants, SOC analysts, students in DFIR programs) to run it against a real or simulated incident and give structured feedback: what did it catch that they'd catch by hand, what did it miss, what was noisy.
- [ ] Track feedback in a `FEEDBACK_LOG.md` and feed concrete issues back into Phase 1/2 backlogs.
- [ ] Publish your false-positive numbers and known limitations openly (a `LIMITATIONS.md` you already have the instinct for) — credibility with this audience comes from honesty about what it doesn't do, not from feature lists.

### Deliverable
A short public writeup: "We ran Drishti Nexus against BOTS v3 and got X% detection coverage on the known ground-truth incidents, Y false positives per 1,000 benign lines, here's what practitioners told us." This is more valuable marketing than the "wow demo" concept and it's true.

---

## Phase 5 — Scoped AI Layer (only after Phase 2 is solid and validated)

Skip the full agentic ReAct framework and ONNX/ML pipeline as a first step. Start minimal.

### 5.1 Narrative Summarization (not autonomy)
- [ ] Bind a small quantized local model (llama.cpp, e.g., a 7–8B instruct model) purely to summarize an already-detected incident (the correlated alert group + surrounding logs from Phase 2.2) into plain English for a report.
- [ ] No tool-calling, no autonomous log querying yet — the model only summarizes data your deterministic engine already found and structured. This keeps it explainable and avoids hallucinated "findings."
- [ ] Make this fully optional and clearly marked as an AI-generated summary, separate from the deterministic alert data.

### 5.2 Natural Language Query (only if 5.1 gets real usage)
- [ ] A constrained NLQ layer that translates questions into your existing query/filter API (not free-form log access) — e.g., "show auth failures outside business hours for host X" maps to existing filters, not an open-ended agent loop.

### 5.3 Full Agentic Investigation / MLOps Anomaly Detection
- [ ] Explicitly deprioritize until 5.1/5.2 prove real usage. This is the most expensive, most fragile part of the original roadmap and the least differentiated from what larger vendors already ship — not where a small tool should compete first.

### Deliverable
An opt-in AI summary feature, evaluated the same way as everything else: does it save analysts time, does it ever say something the underlying data doesn't support (hallucination check against ground truth).

---

## Phase 6 — Commercial Polish (last, and only if the above holds up)

- [ ] UI refresh (dark mode, cleaner dashboard) — cosmetic, do last.
- [ ] Offline license key system (Ed25519-signed `.lic` files) — only once there's something worth licensing.
- [ ] Docker/distributed mode — only if a specific client's environment requires it; keep the single-binary air-gapped mode as the flagship, not an also-ran.
- [ ] Demo video built around real Phase 4 results, not a canned scenario.

---

## Suggested Timeline Summary

| Phase | Focus | Duration | Start Condition |
|---|---|---|---|
| 0 | Baseline & datasets | 3–5 days | Immediately |
| 1 | Harden parsing, custody, correlation basics | 2–4 weeks | After Phase 0 |
| 2 | Adaptive detection, multi-host, ATT&CK, Sigma | 3–5 weeks | After Phase 1 |
| 3 | Reporting/export | 2–3 weeks | Can overlap tail of Phase 2 |
| 4 | Real practitioner validation | Ongoing | Start during Phase 2, never really "ends" |
| 5 | Scoped AI summarization | 2–3 weeks | Only after Phase 2 validated |
| 6 | Commercial polish | Last | Only once 0–4 hold up under real use |

---

## What NOT to Build Yet (explicit non-goals for now)

- Full distributed manager/agent architecture
- ONNX/Isolation Forest anomaly detection pipeline with cloud training loop
- Autonomous multi-step agentic investigation
- Licensing/commercial layer
- Palantir-style UI rebrand

These aren't bad ideas forever — they're just premature relative to fixing parsing edge cases and proving detection accuracy on real data, which is what will actually earn trust from security practitioners.