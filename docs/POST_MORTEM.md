# Build retrospective — living document

Status: implementation, automated verification, live indexed-set/replay verification, and disposition lifecycle checks are complete. Original-evidence and investigation-pivot checks also passed. The silent reference recording is complete and verified. Final narration, submission, and trial cleanup remain open. This document is updated as those steps happen.

## Intended outcome

Demonstrate a trustworthy file-based path from Lantern findings to a real Splunk analyst workflow. Correct evidence handling, clear decisions, repeatable delivery, and an explainable demo take priority over building a separate UI.

## What was built

- Python CLI with validation, preview, and explicit live sending.
- Whole-snapshot checks, preserved original records, readable/structured quality reports, and quarantine.
- Versioned deterministic mapping with selected Alerts vocabulary and custom forensic context.
- Verified HTTPS HEC transport and a destination-scoped SQLite attempt/acceptance ledger.
- Three runnable Splunk searches for current work, finding history, and related evidence/quality.
- Synthetic public examples, automated tests including a real local HTTPS receiver, and clean-package installation proof.

## Plan changes and course corrections

| Observation | Course correction | Why it mattered |
|---|---|---|
| Cloud trial provisioning delayed the setup | After a verified native local Splunk ingestion/search check, use local Splunk | Removed provisioning as a dependency while retaining real product proof |
| Host editable package installation appeared successful but imports failed | Use ordinary installs; configure source discovery only for development tests; verify a wheel outside checkout | Avoided instructions that would fail on the actual machine |
| Local Splunk's default certificate is CN-only | Explicit localhost-only trust/name compatibility profile; retain certificate verification | Made the native installation usable without an insecure TLS flag |
| Independent review found a report-path collision could overwrite a configured credential/trust file | Resolve and protect those paths before any output write; add regression cases | Prevented a real operator configuration edge case from damaging connection material |
| Source timestamps can be more precise than Python datetime | Explicitly reject unsupported sub-microsecond precision rather than silently truncate | Prevents false time-order or tied-revision conclusions |
| Browser authentication expired before live search verification | Continue offline tests/docs and request user sign-in immediately | Separate HEC acceptance from actual indexing proof; do not claim a blocked check passed |
| User requested Photo Booth for an app walkthrough | User selected OBS screen capture after clarification | The recording shows the product workflow; a silent reference and narrated final take are distinct |
| Live Splunk combined automatic JSON extraction with bare `spath`, turning scalar IDs/versions into duplicate multivalues | Clear extracted fields while keeping raw evidence and timestamps, then run explicit extraction; repeat exact-set and replay verification | Prevented misleading grouped copy counts even though only 193 physical events were stored |
| OBS crashed opening settings and later became unresponsive during a recording attempt | Reopened in Safe Mode; use a separate profile/scene collection, hardware Apple H.264, and Matroska; verify a short saved test first | Isolated recording settings and confirmed readable 1080p output before the walkthrough |

## Results established so far

The implemented validator matches the approved private baseline: 200 rows, 193 eligible, 7 quarantined, 33 eligible with warnings, 160 clean, and 24 expected high/critical unreviewed findings. The installed CLI delivered all 193 eligible records to local HEC with 193 acceptance responses, no rejections, and no uncertain outcomes. Independent browser capture subsequently proved the exact 193 ID/version pairs, one stored copy per version, no quarantined IDs, and the exact 24-row queue. A same-ledger replay sent zero HTTP requests and left the indexed set and physical count unchanged. The synthetic lifecycle moved from UNREVIEWED to newer BENIGN, then received older MALICIOUS history: the queue stayed empty, BENIGN stayed current, and all three versions retained the same original detection time.

All 193 originals were preserved. Host and shared-hash pivots matched the expected sets (8 findings on the selected host; 25 shared-hash findings across 9 hosts), and all 33 warning-bearing findings remained searchable. Three private, unscheduled saved reports support the analyst workflow.

The public sample is newly invented and produces four eligible records, one warning, and two queue candidates. Public code and tests exclude supplied assessment records and credentials. Git records meaningful checkpoints rather than one final code dump.

## Tradeoffs to explain in an interview

Whole-file validation catches all members of a conflict before delivery, at the cost of holding this small export in memory. One event per request simplifies outcomes and retries at this scale. SQLite is easy to run and inspect but requires one writer per ledger. Canonical versions make retries predictable, but uncertain delivery can still create physical duplicates; logical searches collapse identical versions.

Rule severity is not analyst judgment. A current-state query selects the entire latest disposition row before filtering status. It must not filter UNREVIEWED first or use the match timestamp to order reviews. Cross-run evidence conflicts cannot automatically retract earlier indexed records; a production correction process needs a stronger source contract and explicit conflict state visible to analysts.

Unknown or inconsistent but identifiable evidence is retained with warnings. The newest local quality report can include cross-record warnings that older indexed versions lack. This prototype intentionally does not resend unchanged source records merely to refresh those contextual flags.

## Next customer-facing validation

Ask analysts whether the queue and pivots match their daily investigations. Confirm severity bands, required context, finding-ID immutability, disposition revision ordering, and reset/correction semantics with Lantern engineering. Then add authenticated API retrieval, pagination/cursors, durable queuing and monitoring, correction/tombstone handling, and customer-specific CIM compatibility where justified.

## Closeout still required

Review the completed live test report and silent reference, rehearse and record the narrated video, verify the refreshed reviewer ZIP and recipient access, and preserve the submitted artifacts. Only after delivery, close the Cloud trial if provisioned and remove/stop the local trial, revoke its token, and verify no paid/billable resource remains. Do not delete the user's entire Splunk account.
