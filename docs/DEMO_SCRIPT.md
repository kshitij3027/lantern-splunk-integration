# Narrated walkthrough — target 3:55

This storyboard targets a 30-second introduction followed by eight demo phases using real terminal and Splunk footage. Capture the actions silently first; remove loading/navigation pauses during editing, then narrate over the completed movie with webcam in OBS. The recording operator need not execute every action within the final playback timestamps.

This script describes the supplied assessment export. Public synthetic examples produce different counts. The illustrated private recording guide contains the exact local paths, selected finding/host, browser links, and reference screenshots; assessment records and screenshots remain outside this public repository.

**Capture status:** the user has supplied a recording uploaded to Google Drive. Its content, duration, and playback have not yet been independently reviewed, so the success statements below remain conditional on the actual recording matching the expected results. The isolated demo source was verified empty when this storyboard was prepared; its recorded first-import results must be checked in the supplied video. Earlier live verification and the silent Splunk reference remain separate evidence.

## Before recording

Start Splunk, sign in, and use All time for historical detection dates. Configure a dedicated demo source in a private profile and use a separate unused acceptance ledger. Scope every browser search to that same source. Keep earlier imported data and its ledger intact. An empty review queue alone does not establish an empty source: also check the source-wide event count.

Install the project with its test dependencies using the README. Activate its virtual environment and work from the project root. For the portable commands below, `input/events.json` is the supplied file in the reviewer ZIP, `local.toml` is the prepared private demo profile, and `output/demo-delivery.sqlite` is the unused demo ledger. Substitute those paths for your environment before recording.

OBS must capture both Terminal and Chrome; the earlier Chrome-only reference scene does not capture Terminal. Keep audio muted for the silent source clips. Use readable text, close unrelated tabs, and keep configuration/token files off screen. Hold completed outputs long enough to read. Do not repeat a first import just to repair video timing.

## Timeline, actions, and narration

| Time | Action on screen | Narration |
|---|---|---|
| 0:00–0:30 | Hold a title card: “Lantern → Splunk — Validate exports · preserve evidence · support investigation.” Narrate with webcam visible; no app actions. | “Lantern already produces security findings. This scenario asks how to make those findings useful to analysts working in Splunk. I built a Python importer that validates Lantern’s JSON exports, maps them into searchable events, and preserves the original evidence. Using Splunk’s existing interface lets analysts prioritize unreviewed findings and investigate related activity. Let me show you that workflow.” |
| 0:30–0:40 | Show the isolated demo queue with All time selected, then its source-wide stored-event count of zero. | “We start with an isolated demo source. Both its review queue and stored-event count are empty.” |
| 0:40–1:05 | Run the dry run below. Hold the summary, then rerun the demo queue and source-wide count searches: both remain empty. | “First, a dry run validates and maps the export without sending anything. Of two hundred rows, one hundred ninety-three are eligible, including thirty-three with warnings. Seven are quarantined. The terminal confirms no network requests, and Splunk remains empty.” |
| 1:05–1:30 | Read the generated validation report. Point to one identity-conflict quarantine reason and one pattern-offset warning. | “The quality report explains those decisions. Quarantine preserves the original record and its rejection reason outside the findings dataset. Usable findings with questionable evidence remain eligible with warnings. Here, conflicting identities are withheld, while an inconsistent pattern offset is preserved and flagged rather than silently repaired.” |
| 1:30–2:00 | Run the first live send. Show its actual acceptance summary, then independently verify 193 stored events and 24 queue findings in the same source. | “Now I send the eligible findings over verified HTTPS to Splunk’s HTTP Event Collector. The local ledger records which versions were accepted. All one hundred ninety-three are accepted. I refresh Splunk to verify indexing: those events are now searchable, and the queue shows twenty-four high or critical findings that are currently unreviewed.” |
| 2:00–2:30 | Search one finding from the queue. Show mapped fields, then expand its original lantern object and paired pattern ID/offset. | “Now I inspect one imported finding. Its mapped fields show the score, host, rule, file path, and hash. The original Lantern record is preserved, including paired pattern IDs and offsets. Severity and analyst disposition remain separate, so a high-scoring match can still be benign.” |
| 2:30–2:55 | Use that finding’s exact host ID in a related-evidence search. Show the eight matching findings. | “Searching this host identifier returns eight related findings. These are existing Lantern matches, not detection rules being run again. Keeping each finding distinct helps the analyst investigate the wider context without losing the original evidence.” |
| 2:55–3:20 | Repeat the import using the same ledger. Show 193 previously accepted and zero HTTP attempts, then unchanged Splunk counts. | “I repeat the same import using the same ledger. It reports one hundred ninety-three previously accepted versions and zero HTTP requests. Splunk’s count stays unchanged. This avoids resending unchanged findings while allowing later disposition versions. Lost responses remain explicitly uncertain: this prototype does not claim exactly-once storage.” |
| 3:20–3:55 | Run the automated tests and show the completed result. Return to the populated queue for the closing proposal. | “All two hundred seventy-nine automated tests pass. I also verified the real indexed identities, quarantine exclusions, repeat imports, and review ordering in Splunk. For a customer pilot, I would agree severity bands and source contracts with analysts, connect to Lantern’s API for incremental retrieval, and strengthen delivery monitoring and correction workflows.” |

## Terminal commands by phase

These are direct commands, not a scripted helper. Run them in order in the same activated environment. Exit code 2 is expected for this supplied file: it means completion with quality issues. Preserve unexpected output and resolve it before narrating success.

### Phase 2 — preview

```sh
clear
lantern-splunk send \
  --input input/events.json \
  --config local.toml \
  --dry-run \
  --output output/demo-preview
```

Expected: 200 rows; 193 eligible, including 33 with warnings; seven quarantined; no network or ledger changes. Rerun both the queue and source-wide count searches: no queue results and zero stored events.

### Phase 3 — quality report

```sh
clear
sed -n '1,12p' output/demo-preview/validation-report.txt
sed -n '/immutable_id_conflict/p' output/demo-preview/validation-report.txt | head -n 1
sed -n '/pattern_offset_out_of_bounds/p' output/demo-preview/validation-report.txt | head -n 1
```

This is an operator report produced by the importer, not a Splunk dashboard. Show the actual reasons, without modifying the original evidence.

### Phase 4 — first live import

```sh
clear
lantern-splunk send \
  --input input/events.json \
  --config local.toml \
  --state output/demo-delivery.sqlite \
  --output output/demo-import
```

Expected: 193 HEC accepted, zero previously accepted, no rejected/uncertain/not-attempted records. Without retries, this uses 193 HTTP attempts. Independently rerun the source-wide count search and wait for indexing: expect 193 stored events. Rerun the source-scoped current queue: expect 24 high/critical UNREVIEWED findings. HEC acceptance alone does not establish indexing.

### Phase 7 — replay with the same ledger

```sh
clear
lantern-splunk send \
  --input input/events.json \
  --config local.toml \
  --state output/demo-delivery.sqlite \
  --output output/demo-replay
```

Expected: 193 previously accepted, zero new HEC acceptances, zero HTTP attempts, and unchanged Splunk counts. Only the report output directory changes; input, destination, and ledger remain the same.

### Phase 8 — tests

```sh
clear
python -m pytest -q
```

Expected: 279 passed. Use the actual result from the recorded run. These are automated importer tests; the independent live Splunk checks establish indexing, query behavior, and review ordering separately.

## Browser actions and continuity

Use the prepared source-scoped searches: queue, total count, selected finding, and exact host. Search templates are in `splunk/searches/`; replace the source filter consistently with the dedicated demo source. Rerun searches using Splunk's search/reload control after ingestion, since a browser refresh can reuse an old job.

For inspection, select Events and expand the nested `lantern` object using its JSON expansion controls. Show the mapped values and original file/rule/pattern evidence. For the host pivot, filter using the selected finding's exact host ID and select Statistics. Do not imply a special recommendation button or new detection-rule execution.

The introduction and eight demo phases total 235 seconds: 30 seconds of context plus 3:25 of app footage. Detailed shared-hash and synthetic lifecycle demonstrations are omitted from this short movie; their completed checks remain in `TEST_CASES.txt` and the private verification records. Existing populated-source footage must not be relabeled as the new source filling.

## Final narration and review

Start the silent video with the 30-second title card, then edit the real app clips to the eight demo boundaries above. The complete video targets 3:55 including the introduction; do not add another intro or countdown. Play the completed silent movie in OBS alongside webcam capture and microphone narration. Rehearse twice, check readable fields and synchronized narration, and play back the final exported file before handoff. The user-supplied recording is uploaded; its content/duration/playback review, recipient-access verification, and post-delivery trial cleanup remain outstanding. The target duration above is the storyboard duration, not a measurement of the uploaded file.
