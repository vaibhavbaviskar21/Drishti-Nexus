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