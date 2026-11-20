You are working on Drishti Nexus, a Go-based offline/air-gapped security log
analysis tool. Follow the implementation plan in
Drishti_Nexus_Implementation_Plan.md (in the repo root) exactly, phase by phase.

Rules for how you work on this project:

1. Work ONE phase at a time, in order (Phase 0 → 1 → 2 → 3 → 4 → 5 → 6).
   Do not start a later phase's tasks until the current phase's deliverable
   exists and its checklist items are done.

2. Before writing any code for a phase, re-read that phase's section in
   Drishti_Nexus_Implementation_Plan.md and restate its task checklist and
   deliverable back to me in your own words, so I can confirm scope before
   you start.

3. Every phase must end with its stated deliverable actually produced:
   - Phase 0: a BASELINE.md with real numbers from running the benchmark
     harness against the test datasets.
   - Phase 1: updated BASELINE.md showing improvement, CHAIN_OF_CUSTODY.md,
     CI green on lint/tests/gosec.
   - Phase 2: updated BASELINE.md, ATTACK_MAPPING.md, a multi-host
     correlation demo.
   - Phase 3: a sample HTML/PDF incident report.
   - Phase 5: an opt-in AI summary feature with a hallucination check against
     ground truth.
   Do not mark a phase complete without its deliverable existing as a real
   file/artifact in the repo.

4. Never silently skip a task in a phase's checklist. If you think a task
   should be skipped or deferred, say so explicitly and ask me before
   proceeding.

5. Respect the "What NOT to Build Yet" list at the end of the plan. If I ask
   for something on that list before its phase, remind me it's listed as
   premature and ask whether I want to override that.

6. Keep changes test-covered: any new parser behavior, detection rule, or
   correlation logic needs a unit test, and anything touching the full
   pipeline needs an integration test against the datasets from Phase 0.

7. Maintain the proct's core identity throughout: single binary,
   offline-first, read-only access to source logs, deterministic/explainable
   detection as the default (AI stays optional and clearly labeled).

8. After finishing a phase's deliverable, stop and summarize: what changed,
   what the new baseline numbers are (if applicable), and what's next in the
   plan. Wait for my go-ahead before starting the next phase.

Start by reading Drishti_Nexus_Implementation_Plan.md in full, then begin
with Phase 0: set up the benchmark harness and help me identify/download the
public datasets (BOTS, EVTX-ATTACK-SAMPLES, a benign log sample) referenced
in that phase.

---

## Project log (kept current by Claude; the rules above are the owner's)

**What it is:** a single offline Go binary that parses security logs (syslog, auth, Apache, JSON, CEF, LEEF, CSV, Windows Event XML, YAML-defined formats), detects attacks with deterministic rules plus Sigma, keeps a SHA-256 chain of custody for every result, and shows it in a local web dashboard and HTML/PDF reports. Optional local-LLM summaries are labeled and checked against the facts.

**Layout:** `cmd/drishti` (CLI), `cmd/benchmark`, `cmd/genbenign` · `internal/parser` (formats) · `internal/detection` (rules, adaptive thresholds, ATT&CK, compliance) · `internal/sigma` · `internal/pipeline` (time-merged multi-file runs) · `internal/audit` (custody) · `internal/ecs` (ECS export) · `internal/report` (HTML/PDF) · `internal/ai` (opt-in summaries) · `internal/web` (dashboard) · `rules/sigma`, `parsers/` (shipped definitions) · `docs/` · `testdata/`.

**Commands:** `go test ./...` · `golangci-lint run ./...` · `gosec -quiet -conf .gosec.json ./...` · `bash scripts/fetch-datasets.sh && make genbenign` (datasets) · `go run ./cmd/benchmark -suite -sigma rules/sigma` · `drishti scan -sigma rules/sigma -parsers parsers -report r.html -pdf r.pdf -ecs e.ndjson logs/` · `drishti serve logs/`.

**Gotchas:**
- Windows Defender quarantines real attack telemetry. `testdata/fixtures/mordor_sigma_events.json` is defanged for that reason; keep payloads out of committed fixtures.
- `core.autocrlf=true` on this machine. `.gitattributes` pins LF, and verbatim LogHub fixtures are `-text` (CRLF kept).
- Every file open must go through `audit.OpenEvidence` (read) or `storage.CreateOutput` (write); `internal/audit/readonly_test.go` enforces it.
- Integration tests pin alert counts per dataset. A change that moves a number must update `BASELINE.md`.

**History**
- 2025-12-31 Initial prototype (`f5f55a9`).
- 2026-10-04 Phases 0–1: benchmark harness, datasets, parser hardening, chain of custody, SQLite, CI (merged in PR #1 on 2026-10-31).
- 2026-10-31 2.3 ATT&CK mapping; 2.2 multi-host correlation with Lateral Movement rule and demo (PR #1).
- 2026-11-01 2.6 ECS export, CEF/LEEF/CSV/XML parsers (PR #2), YAML parsers, Dockerfile; 2.1 adaptive thresholds; 2.5 FP tuning (0.92 FP/1k); 2.4 Sigma engine + 3 rules; Phase 3 HTML/PDF reports; Phase 5 opt-in AI summaries with grounding check; Phase 6 UI refresh; Phase 4 feedback log and write-up draft.
- 2026-11-06/07 Sustained-throughput benchmark (`-repeat`), compliance references (PCI DSS/ISO 27001/HIPAA) in reports, project site `docs/site/`, UI design tokens.
- 2026-11-20 Defanged the Sigma fixture (Defender had quarantined it); filled the throughput numbers in the write-up; this log.

**Status:** all planned engineering for Phases 0–6 is done on branch `phase2-to-6`. Tests, golangci-lint and gosec pass locally. PR #2 (2.6 subset) is open; its content is included in `phase2-to-6`.

**Open items**
- Phase 4 (owner): post the write-up (`docs/VALIDATION_WRITEUP.md`), recruit 3–5 practitioners, fill `FEEDBACK_LOG.md`.
- Phase 5: run a real local model (llama-server/Ollama) and measure unverified-summary rate. No runtime is installed here.
- Not built, by plan: NLQ (5.2), agentic investigation (5.3), licensing, distributed mode, demo video (needs Phase 4 results).
- Known gaps: Sigma aggregations; BOTS ingestion; `serve` does not follow growing files; JS has no automated tests.
