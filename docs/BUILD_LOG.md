# Build log

## October 1, 2026 — setup history (reconstructed from verified notes)

Cloud trial provisioning delayed the initial setup. An official native macOS ARM Splunk Enterprise installation was checksum/signature verified and run locally. The user accepted terms, created credentials, and signed in. A project-scoped HEC token was created after approval; Web, management, and HEC listeners were verified on loopback. A synthetic probe was accepted and independently found in Splunk search. No assessment data was ingested during this setup.

## October 1, 2026 — approved baseline and repository

The user approved execution. Created the public GitHub remote first, then an isolated local Git repository and connected it, matching the requested sequence. Added project scaffolding, approved-plan summary, and decision record. Public source material is synthetic; the detailed private review plan and provided files are excluded. Validation/mapping and delivery/state implementation are delegated with separate test ownership; the parent integrates the CLI and verifies end to end.

Validation: Git root resolves to this project directory; remote identity verified. No application behavior claimed at this milestone.

## October 1, 2026 — installation path correction

The first configuration tests exposed an editable-install discovery issue on the host: the generated `.pth` file had the macOS hidden flag, which Python 3.14 deliberately skips. Chose ordinary package installation for the reviewer path, and an explicit source path for development tests. No system or Python security behavior was changed. The release check will install a built package in a clean environment and run the actual CLI outside the checkout.

## October 1, 2026 — validation, mapping, and operator workflow

Implemented full-snapshot validation, canonical identity/version hashes, original evidence preservation, deterministic mapping, and terminal/JSON/text reports. CLI supports validate, dry-run, and live send with explicit destination and state. Ambiguous duplicate JSON keys and non-finite numbers fail before delivery. Reports use atomic owner-only files and cannot overwrite the input/configuration/ledger.

Verification: 169 configuration/CLI/validation/mapping cases passed. The private input reproduces the planned counts exactly: 200 rows, 193 eligible, 7 quarantined, 33 eligible warnings, 160 clean, 24 high/critical UNREVIEWED. An actual Python HEC request using the local CA and certificate name received code 0 for a clearly synthetic smoke event. Independent indexing verification remains a separate step.

## October 1, 2026 — delivery and independent review

Integrated verified HTTPS transport, durable pending attempts, acceptance ledger, bounded retries, recovery of interrupted attempts, and destination-scoped replay. The installed CLI received 193 HEC acceptance responses for 193 assessment candidates; no rejection or uncertainty was reported. Search indexing remains awaiting browser sign-in.

Independent review found two boundary issues and both received regression tests: report output could collide with configured token/CA paths, and timestamps beyond microsecond precision could silently truncate. Outputs now protect all configured input/trust/credential/state paths before writing; unsupported precision is explicitly rejected. Token-file permissions are enforced. Possible-duplicate delivery is visible in the terminal as well as JSON.

Validation at this checkpoint: **279 automated cases passed** on Python 3.14.2/macOS, including a real generated-certificate HTTPS receiver and subprocess ledger locking. A wheel installed into a fresh environment outside the checkout ran the actual CLI and synthetic dry run successfully. Live browser indexing, replay counts, and disposition lifecycle checks remain outstanding and are not counted as passed.

## October 1, 2026 — review materials and portable verification

GitHub Actions passed the core checkpoint on both Python 3.11 and Python 3.14 under Ubuntu. Added a detailed plain-text report covering all 97 test functions / 279 parameterized cases, field-by-field mapping decisions, a timed narration/action script, and a living retrospective. Created and validated three synthetic lifecycle fixtures for the pending live current-state check.

A second independent documentation audit checked claims against the implementation and outstanding browser work. It corrected test-count/lifecycle wording and prompted explicit reviewer-package input paths and native Splunk start/stop instructions. The recording is still pending; no video artifact or live search verification is claimed.

## October 1, 2026 — ZIP reproduction checkpoint

Built a curated private reviewer ZIP containing source, tests, documentation, synthetic examples, and the unchanged supplied input/schema. Verified its checksum manifest, excluded live secrets/configuration/ledger/cache/virtual environments, then extracted into a fresh directory and installed into a new virtual environment. All 279 tests passed again; the installed CLI outside the source tree reproduced the assessment preview (193 eligible, 7 quarantined, 33 warnings, exit 2). This is a review candidate; browser E2E, recording, upload/access verification, and final submission are still pending.

## October 1, 2026 — independent live Splunk reconciliation

After browser sign-in, the initial grouped query appeared to show four copies per finding. Live diagnostics isolated duplicate automatic-plus-explicit JSON extraction: two ID values and two version values created a grouped cross-product, despite 193 physical events. Searches now retain raw evidence/timestamps before explicit extraction. Browser-captured pair sets then exactly matched all 193 eligible source versions, each with one stored copy; all five distinct quarantined IDs were absent. The exact 24 queue pairs matched the independently derived expected set.

The controlled installed-CLI replay reported 193 previously accepted versions and zero HTTP attempts. A second complete browser pair capture proved the same 193 physical events and identical logical set. An independent agent checked the captured files and replay report against the validator output. No acceptance count was substituted for indexing proof.

The user chose OBS for screen recording. A separate profile and scene collection capture only the Chrome window at 1080p with audio muted. OBS crashed once opening settings and recovered in Safe Mode; no crash report was uploaded. Recording starts after the remaining live lifecycle and investigation checks pass.

## October 1, 2026 — live investigation and lifecycle checks complete

The synthetic lifecycle was ingested in three stages: UNREVIEWED, newer BENIGN, then an older MALICIOUS revision arriving last. Browser checks proved queue counts 1→0→0, history counts 1→2→3, BENIGN still current, and unchanged original detection time. All 193 nested originals matched mapped source evidence. Selected-host results matched 8 expected findings; the shared-hash pivot matched 25 across 9 hosts; all 33 warning findings and the unknown TRIAGED status remained visible. Saved all three reports privately with no schedule. The independent test report now marks all live application checks passed.

OBS also became unresponsive during a recording attempt. Recovered it through Activity Monitor and reopened in Safe Mode. Changed the isolated reference profile to hardware Apple H.264 and Matroska at 1920×1080/30fps. An 18-second test saved successfully and its extracted frame showed a readable Splunk queue. Browser policy blocks local file pages, so the reference captures the live Splunk workflow only; the final user-narrated script includes terminal/report steps using additional capture sources. No blocked file access was worked around.

## October 1, 2026 — reference recording and release preparation

Recorded the actual Splunk workflow in OBS: 24-row queue, original Lantern evidence, host and shared-hash pivots, quality warnings, complete synthetic review history, BENIGN current state, empty reviewed synthetic queue, and the assessment queue again. Saved the original Matroska file and losslessly remuxed its video to a silent H.264 MP4 (1920×1080, 30fps, 283.4 seconds). Full decoding reported no errors. Inspected a contact sheet and full-resolution frames, and confirmed QuickTime playback advances. This is a 4:43 reference, not the final 3–4 minute narrated assessment submission.

The live-query correction/checkpoint `d54b914` also passed the Python 3.11/3.14 CI matrix. The final code ZIP is generated from committed public files plus the unchanged private assessment JSON/schema and reviewer instructions. Its separate private checksum/reproduction record identifies the exact refreshed artifact; video and credentials are excluded from the code ZIP. Rehearsal, final narration, Drive delivery/access verification, and post-delivery trial cleanup remain open.
