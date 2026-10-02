# Narrated walkthrough — target 3:40

This is a rehearsal script for the supplied assessment export in the local prototype. Use the submitted README and input path in the reviewer ZIP. The public repository contains only synthetic examples; those produce different counts. The final narrated take should follow live verification and two rehearsals.

## Before recording

Start local Splunk and sign in. Have the assessment findings already imported and independently verified. Open the three private saved reports, select All time, and pick one high/critical unreviewed finding with useful related host/hash evidence. Keep one original input record and the readable validation report available beside Splunk. Close unrelated browser tabs and notifications. Hide all configuration/token files and do not show developer tools or authenticated request headers.

Prepare these two commands, substituting private local paths before recording:

```sh
lantern-splunk send --input input/events.json --dry-run --output output/demo-preview
lantern-splunk send --input input/events.json --config local.toml --state output/delivery.sqlite --output output/demo-replay
```

Use the **same ledger that performed the original import** for the replay. A fresh ledger would resend events. In the developer workspace, the assessment input, profile, and ledger are in the private paths recorded in the private runbook. Dry run and replay return 2 because the supplied file has quality issues; they still complete successfully. Do not present a replay as a first import.

## Timeline, actions, and narration

| Time | Action on screen | Narration |
|---|---|---|
| 0:00–0:25 | Open Splunk's current review queue; title visible, All time selected | “This prototype brings Lantern findings into the place a security analyst already works: Splunk. Lantern has already matched detection rules against files. My integration makes those findings searchable, preserves the evidence, and helps the analyst distinguish an urgent match from a match that has already been reviewed.” |
| 0:25–0:55 | Run dry-run command; show terminal summary and report location | “The operator supplies a JSON export to a small Python importer. It validates the entire file before sending anything. This file contains two hundred rows: one hundred ninety-three are usable, including thirty-three with warnings. Seven are quarantined because essential information is missing or finding identities conflict. Every row remains accounted for.” |
| 0:55–1:25 | Open readable validation report; show one quarantine reason and one warning | “Quarantine means preserving the original row with a reason and withholding it from the normal findings dataset. A usable finding with questionable evidence stays visible with a warning. For example, I preserve inconsistent file-size or pattern-offset evidence instead of pretending I can repair it. The report supports the person operating the integration.” |
| 1:25–2:00 | Return to 24-row queue; select a finding, switch to its event/history view, inspect normalized fields and original `lantern` evidence | “These twenty-four findings are high or critical and currently unreviewed. The original rule score is retained alongside my explicit severity bands. Severity and analyst disposition are separate: a high-scoring match can later be reviewed as benign. Opening a finding lets me trace the host, file hash, rule, and pattern evidence back to the original Lantern record.” |
| 2:00–2:30 | Copy a host ID or hash and run its exact related-evidence filter; show multiple findings | “I can pivot using this host, collection, or hash to retrieve related findings. These are existing matches, not newly run detection rules. I preserve individual finding identities because a shared hash or multiple matches does not by itself prove several compromised machines.” |
| 2:30–3:05 | Run repeat-send command; show 193 previously accepted, zero HTTP attempts; briefly show separate synthetic lifecycle proof if time permits | “This export was imported earlier. Repeating it now sends zero new requests because the local ledger remembers accepted versions. A changed analyst disposition creates a new version. Searches order those reviews using disposition time while retaining the original detection time. Lost responses remain explicitly uncertain; I do not claim exactly-once storage.” |
| 3:05–3:40 | Show tests summary and return to queue | “I verified both the importer and real Splunk results, including the exact finding identities, repeat imports, and review updates. The implementation includes tests for malformed data, conflicting revisions, delivery failures, and certificate verification. For a customer pilot, my next steps would be to agree the severity and source contracts with analysts, add a real Lantern API and incremental retrieval, and strengthen operational delivery and correction workflows.” |

The live-index/replay/lifecycle sentence must only be used after those checks are marked passed in `TEST_CASES.txt`. Cut a detailed lifecycle demonstration before rushing the central analyst journey; keep its tested behavior in the narration and interview notes.

## Recording and review

Use a 1920×1080 capture if legible; increase terminal/browser text size before starting. Target 3:40 and remain under four minutes. Rehearse once for navigation and once with a timer. Record a complete take, then play back the exported file to check readable fields, clear audio, correct duration, and absence of credentials or unrelated personal information.

OBS can capture the actual app screen and microphone. Photo Booth normally captures the webcam; the requested capture method is awaiting clarification. A webcam-only recording would not show the Splunk workflow. Do not label an unrecorded or unreviewed video as a finished submission.
