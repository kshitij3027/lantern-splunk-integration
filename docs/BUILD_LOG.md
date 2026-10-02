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
