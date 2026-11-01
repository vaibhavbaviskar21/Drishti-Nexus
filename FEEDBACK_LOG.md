# Practitioner Feedback Log (Phase 4)

Phase 4 of the plan validates Drishti Nexus with real practitioners: post it with a public dataset in DFIR communities, recruit 3–5 IR consultants, SOC analysts or DFIR students, and feed what they report back into the backlog. That outreach is done by a person, not the tool. This file is where its results go.

**Status (2026-11-01): no practitioner sessions yet.** Nothing below is invented. Every row must come from a real session.

## How to run a session

1. Give the participant the release binary and one public dataset with known ground truth, for example `testdata/datasets/loghub-ssh/SSH.log` (internet brute force) or the Mordor PsExec / Mimikatz JSON (fetch with `scripts/fetch-datasets.sh`).
2. Have them first triage the data by hand or with their usual tools, and note what they find.
3. Then run: `drishti scan -sigma rules/sigma -report report.html <dataset>` and `drishti serve`.
4. Ask the questions below and record the answers in a row. Quote the participant; don't paraphrase findings into claims.

**Questions**
- What did Drishti Nexus catch that you also caught by hand?
- What did you catch that it missed?
- Which alerts were noise for you, and why?
- Was every alert explainable from its evidence lines and details?
- Would you attach the HTML/PDF report to a case file as is? What's missing?

## Sessions

| # | Date | Role / experience | Dataset | Caught by both | Missed by tool | Noise | Report usable? | Issues filed |
|---|---|---|---|---|---|---|---|---|
| — | — | — | — | — | — | — | — | — |

## Backlog items from feedback

| Source session | Item | Phase it feeds | Status |
|---|---|---|---|
| — | — | — | — |

## Where to post (from the plan)

- r/DFIR, r/netsec
- SANS / DFIR Discord
- Velociraptor and Wazuh community forums

Use [docs/VALIDATION_WRITEUP.md](docs/VALIDATION_WRITEUP.md) as the post. It contains only measured numbers and openly links [docs/LIMITATIONS.md](docs/LIMITATIONS.md).
