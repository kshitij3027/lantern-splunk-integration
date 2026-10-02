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
