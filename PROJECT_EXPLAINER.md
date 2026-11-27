# Drishti Nexus: Project Explainer

## 30-second pitch

Drishti Nexus is a security log analysis tool that runs as **one offline program**, with no internet, no server and no installation. An incident responder points it at a folder of logs from a compromised machine. It reads them without ever modifying them, detects attacks with rules a human can verify, links related events across machines into incidents, and produces an evidence-grade report in which every alert cites the exact log line and the file's SHA-256 hash. It is built for air-gapped and sensitive environments (government, critical infrastructure, forensics), where cloud SIEMs are not an option.

## The problem

- Incident responders often get logs on a USB stick from a network that must stay offline. Big SIEMs (Splunk, Elastic) need servers, licences and ingestion pipelines. Small scripts don't preserve evidence and break on real-world log formats.
- Logs come in many formats: syslog, Windows events (JSON, XML, CSV), vendor CEF/LEEF, web logs. Analysts lose time writing parsers before they can even start.
- Detection tools are noisy. The original prototype of this project raised **570 false alarms per 1,000 benign log lines**.
- In forensics, results must hold up as evidence: which files, which version of the rules, who ran it, and proof the logs weren't altered.

## How it works

**Pipeline (one Go binary, single process):**

1. **Evidence intake:** every file is SHA-256 hashed before analysis, opened **read-only**, and re-hashed afterwards to prove it didn't change. A test fails the build if any code path opens files another way.
2. **Parsing:** built-in parsers for syslog (all common variants), Linux auth, Apache, JSON, Windows Event XML, CSV, CEF and LEEF. New formats can be added as **YAML files** with no code. Each entry gets a quality flag (Clean, Partial or BestEffort), so you know how much to trust it. Edge cases are handled explicitly: time zones, daylight-saving gaps, missing years, broken encodings, multi-line records.
3. **Time-ordered merge:** many files (several hosts, rotated logs) are merged by event time, so activity across machines is analysed in the order it happened.
4. **Detection:**
   - **7 built-in rules:** brute force, excessive failed logins, privilege escalation, suspicious commands, injection, off-hours activity, lateral movement.
   - **Sigma rules,** the community standard format, evaluated by our own offline engine (including `count()` rules such as "more than 4 usernames from one IP in 10 minutes").
   - **Adaptive thresholds:** each source learns its normal failure rate, but the fixed threshold is always the floor, and attacks are never learned as "normal".
5. **Correlation:** related alerts become incidents. The cross-host rule links "password brute-forced on server A" with "the same account then logs into server B".
6. **Outputs:**
   - Every alert is tagged with **MITRE ATT&CK** techniques and mapped to compliance controls (PCI DSS, ISO 27001, HIPAA).
   - **Reports:** a self-contained HTML and PDF incident report, JSON/CSV, and an **ECS** export for SIEMs.
   - **Dashboard:** a local web dashboard that can follow a live log.
7. **Optional AI summary:** a *local* language model (loopback only) can write a plain-English incident summary. A deterministic checker verifies every IP, user, host, time, count and ID in it against the real data, and the summary is labeled "AI-generated — not evidence".

**Tech stack:** Go (standard library first), SQLite via a pure-Go driver (optional persistence), vanilla HTML/CSS/JS dashboard embedded in the binary (strict Content-Security-Policy), GitHub Actions CI (Linux and Windows tests with the race detector, golangci-lint, gosec, Docker build).

## Talking points

**Measured results** (public datasets: LogHub SSH/Linux, OTRF Mordor Windows attacks, plus a 50,000-line benign week):

- **False positives fell 99.8%:** 569.9 → **0.92 per 1,000 benign lines**. Privilege-escalation alerts on legitimate `sudo` went from 100% of uses to **0%**.
- **Detection: 7 of 7 documented attack behaviours** (it was 6 of 7 until 2026-11-27), including Mimikatz credential dumping from LSASS, an rpc.statd exploit (**all 7 attempts, 0 false positives**), and PsExec lateral movement with valid credentials.
- **The last miss closed:** that PsExec hop from WORKSTATION5 to WORKSTATION6 used real credentials, so the brute-force-based lateral rule couldn't see it. A new rule pairs the network logon with the service install 2 ms later and joins it to WORKSTATION5's incident. The logs reveal WORKSTATION5's address only 95 ms *after* the install, so the alert is completed and linked once that's known.
- **Parsing:** syslog went from **0% structured** in the prototype (everything fell to raw text) to **100%** on every dataset. The same 2,000 SSH events given as raw syslog and as CSV produce **identical alerts**.
- **Speed and memory:**
  - Prototype: did not finish the 655k-line SSH log in 15 minutes (quadratic window scans).
  - Now: about **35,000 lines/s sustained** on one core of a 2-core laptop i3 (≈3 billion lines/day), with **memory flat at a 10 MB peak heap** after 6.5 million lines.
  - Windows JSON runs at about **2,600 events/s**, roughly 13× costlier per event.
- **Password-spraying rule:** **303 alerts from 124 attacking IPs** on the SSH dataset and **0 on benign data**. I verified the most suspicious-looking alert against the raw log: 28 usernames in 7 minutes.
- **AI hallucination checker:** caught **10 of 10 planted hallucination types** (wrong IP, invented host, wrong count, time outside the incident…) and passed 5 of 5 faithful summaries. **Honest gap: not yet run against a real model**, because none is installed on the dev machine.

**Security and evidence handling:**
- Every result can be traced to the exact files (SHA-256), rule and parser definitions (hashed), config and user, through a hash-chained audit log.
- Attacker-controlled log text is never rendered as HTML (escaping is tested). The dashboard binds to localhost and sends a strict CSP.
- I found and fixed a real issue in the report code: a template helper that bypassed HTML escaping (flagged by gosec).

**Honesty about results:**
- Numbers are pinned in integration tests: if a change moves an alert count, CI fails until `BASELINE.md` explains why.
- I corrected my own earlier claims. Phase 0 reported "100% parse success", but every syslog line was actually falling through to the generic parser. The correction is documented.
- Windows Defender quarantined a test fixture containing a real attack payload. I defanged the payload rather than weaken the antivirus, and documented it.

**Testing:** unit tests per parser and rule (including exact threshold boundaries), integration tests on the public datasets, mutation checks (deliberately breaking code to prove a test catches it), a WebSocket end-to-end test for the live dashboard, and CI on Linux and Windows with the race detector.

**Accessibility (dashboard):** semantic HTML, keyboard-navigable tabs and drawer (Esc closes, focus returns), visible focus, aria labels, light and dark themes, no horizontal scroll at laptop widths.

## Features built so far

- 2025-12-31: First prototype: CLI with scan, tail and analyze, 6 keyword rules, basic web dashboard.
- 2026-10-04: Benchmark harness and public datasets with checksums; honest baseline numbers.
- 2026-10-04: Parser hardening (time zones, DST, missing years, encodings, multi-line JSON, stack traces) and a parse-quality flag on every entry.
- 2026-10-04: Chain of custody: SHA-256 before/after, read-only access enforced by a test, hash-chained audit log, hashes in every export.
- 2026-10-04: Detection correctness (event-time windows, per-IP keys, attempt de-duplication), alert linking, incidents; optional SQLite with crash-resume.
- 2026-10-31: MITRE ATT&CK tag on every alert.
- 2026-10-31: Multi-host analysis and the "lateral movement" rule (brute force on A → login on B).
- 2026-11-01: ECS export for SIEMs; CEF, LEEF, CSV and Windows XML parsers; YAML-defined parsers; Docker image.
- 2026-11-01: Adaptive per-source thresholds; false-positive tuning (per-host working hours, corroborated privilege escalation).
- 2026-11-01: Offline Sigma rule engine with shipped rules (LSASS dumping, malicious service install, format-string exploit).
- 2026-11-01: HTML/PDF incident reports; opt-in local AI summaries with a hallucination checker; redesigned dashboard.
- 2026-11-07: Sustained-throughput benchmark; compliance references (PCI DSS, ISO 27001, HIPAA) in reports; project website.
- 2026-11-20: Live dashboard that follows a growing log; Sigma `count()` rules; SSH password-spraying rule; ATT&CK names for Sigma techniques.
- 2026-11-27: "Remote Service Execution" rule: PsExec-style lateral movement with valid credentials, linked across hosts (detection score 6/7 → 7/7).

## What's next

1. **Real-world validation (Phase 4):** put the tool and write-up in front of 3–5 practitioners and DFIR communities, and log what it caught, missed and over-alerted.
2. **Run the AI summary against a real local model** and measure how often summaries come back unverified.
3. **Close known gaps:**
   - Splunk BOTS ingestion;
   - following several live files at once;
   - Sigma `near` and `<` conditions;
   - automated tests for the dashboard JavaScript.
4. **Deliberately not yet built:** natural-language queries, autonomous AI investigation, licensing, distributed mode. They come only once real users justify them.

## Likely interview questions

**Why Go?** It compiles to a single static binary for Windows, Linux and macOS with no runtime, which is exactly what an air-gapped USB deployment needs. Its standard library covers HTTP, crypto, templates and JSON, so there are few dependencies to audit.

**Why not just use Splunk or Elastic?** They need servers, licences and ingestion. Drishti Nexus targets the first hours of an investigation on an isolated network. It can also *feed* those tools through its ECS export.

**How do you know your detection is good?**
- I measure it against public datasets whose publishers document what attacks they contain, plus a benign set where every alert is by definition a false positive.
- The numbers are pinned in CI.
- I report misses, not just hits. The score was 6 of 7 until I built the rule for the missing case; I kept the history visible.

**How did you cut false positives from 570 to under 1 per 1,000 lines?**
- Most came from bugs, not tuning: keyword rules firing on any mention of "root" or "sudo", windows computed from wall-clock time instead of event time, and one login attempt counted 3 times because sshd writes 3 lines.
- After fixing those, per-host behaviour profiles removed half of what was left.

**What are adaptive thresholds, and can an attacker abuse them?** Each source learns its normal failure rate (an exponentially weighted mean plus 3 standard deviations), with the fixed threshold as the floor. To prevent poisoning, any window that already looks like an attack is never learned. A test proves a 5-hour attack cannot raise its own threshold.

**How does the chain of custody work?** Files are hashed before analysis and re-hashed after, and access is read-only (enforced by a test that scans the code). Each session is appended to a hash-chained audit log with the config, rule and parser hashes and the OS user. Every report row cites the file, line and hash.

**Why build your own Sigma engine?** The requirement was offline and single-binary. The engine supports the common subset (field modifiers, wildcards, boolean conditions, `count()` aggregations) and *skips* anything unsupported with a reason, instead of half-applying it.

**How do you stop the AI from making things up?**
- The model only sees facts the deterministic engine already found, with no tool access.
- A separate deterministic checker extracts every concrete claim (IPs, hosts, users, counts, times, IDs) and verifies it against those facts. Anything unsupported marks the summary UNVERIFIED.
- Limits I state openly: it can't judge paraphrased reasoning, and it hasn't been measured on a real model yet.

**How did you detect lateral movement without a brute force to key on?** On the target host, a network logon (Windows 4624, type 3) followed within minutes by a service install (7045/4697) is the PsExec pattern. To link it to the attacker's host, I learn which IP belongs to which host from the connections each host itself initiates. In the real data that mapping arrives 95 ms *after* the install, so the alert gets completed and linked retroactively. A unit test reproduces that ordering.

**What was the hardest bug?** The prototype's "100% parse success" was false: plain syslog matched no parser, so every line silently fell back to raw text with a fake timestamp. Finding it meant distrusting my own metric, defining "structured" properly and re-measuring. Phase 0's numbers were corrected publicly in `BASELINE.md`.

**How does it scale?** One core handles about 35k syslog lines/s with flat memory. For larger feeds, the design is to run one process per host or source (it is single-threaded by choice) rather than build distributed mode before anyone needs it.

**What would you do differently?** Set up the honest benchmark and the pinned integration tests *before* writing features. Every early improvement claim had to be re-measured once real datasets came in.
