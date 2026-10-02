# Investigating Lantern findings in Splunk

The three files in [`splunk/searches`](../splunk/searches/) are complete, executable searches. Paste one into Splunk Search & Reporting and run it. Select **All time**; the searches also set `earliest=0 latest=now` explicitly because detection timestamps can be historical.

Their first line selects the project index `volexity_lantern`, source `lantern:assessment`, and sourcetype `lantern:indicator_match`. If importing a synthetic example under another source, change that source deliberately in your copy. Keep a synthetic lifecycle test on its own source so it cannot change assessment counts. Setup smoke events have a different sourcetype and are excluded.

## Save the three searches

After running each query successfully, use **Save As → Report**, keep its permissions private, and give it the corresponding title below. Retain its search text and All time range. No alert schedule or dashboard is required.

| File | Suggested report title | Result |
|---|---|---|
| [`01_current_queue.spl`](../splunk/searches/01_current_queue.spl) | Lantern — Current review queue | One current row per high/critical UNREVIEWED finding, highest score first |
| [`02_finding_history.spl`](../splunk/searches/02_finding_history.spl) | Lantern — Finding history | Every distinct source version, with the complete preserved source evidence |
| [`03_related_evidence.spl`](../splunk/searches/03_related_evidence.spl) | Lantern — Related evidence and quality | Current findings, hash relationships, and evidence requiring attention |

## 1. Prioritize current work

The work queue extracts JSON with `spath`, sorts **complete rows** by descending disposition rank and numeric revision time, then uses `dedup id`. Only after that does it filter for `UNREVIEWED` and high/critical severity. This keeps an older unreviewed version from reappearing after an analyst reviews the finding.

`_time` remains the original detection time across revisions. It does not decide which disposition is current. Independent `latest()` aggregations over several fields could select inconsistent evidence; these searches retain a single complete version instead. `sort 0` avoids Splunk's default sort-result limit, at the cost of retaining the full result set for this small prototype. See the official [sort](https://help.splunk.com/en/splunk-enterprise/search/spl-search-reference/10.0/search-commands/sort) and [dedup](https://help.splunk.com/en/splunk-enterprise/search/spl-search-reference/10.0/search-commands/dedup) references.

The `event_version` tie-breaker provides deterministic selection for equivalent duplicate copies. It does **not** resolve two contradictory dispositions at the same revision time. The importer reports those conflicts; an already indexed conflict needs operator investigation. A later UNREVIEWED record without a revision timestamp cannot prove a reset and retains baseline ordering.

Severity is the rule's score band, while disposition is analyst judgment. A high-severity finding marked BENIGN remains searchable in history and related evidence, but leaves this queue.

## 2. Inspect a finding and its history

The history search runs without editing and initially shows all findings. To inspect one, insert an exact-ID filter immediately after `| spath`, for example:

```spl
| where id="synthetic-finding-001"
```

Replace the example literal with an ID copied from your result. This is an exact equality expression, so wildcard characters in an ID do not become a pattern. Escape `\` and `"` inside a quoted literal. A nonexistent ID correctly returns no results.

History deduplicates on **both** `id` and `event_version`, preserving different source revisions. `delivery_copies` counts identical indexed copies before this deduplication; it can reveal a resend after an uncertain delivery. It is a count of stored events, not an importer attempt count.

Inspect `lantern_evidence` to trace normalized fields back to the original source JSON. It retains collection/requestor details, rule versions, file owner and hash, and each matched pattern's paired ID and offset. An empty normalized table cell does not mean the original value was deleted. For Splunk's expandable event view, remove the final `table` command and inspect `_raw`. [Explicit JSON extraction with spath](https://help.splunk.com/en/splunk-enterprise/search/spl-search-reference/10.0/search-commands/spath) makes the searches independent of an unstated sourcetype field-extraction setting.

## 3. Pivot to related evidence or quality issues

The related-evidence search runs without edits and initially shows all current findings. After the `quality_attention` calculation and before the final `sort`/`table`, insert **one** exact filter using a value copied from a result:

```spl
| where host_id="synthetic-host-001"
```

```spl
| where collection_id="synthetic-collection-001"
```

```spl
| where file_hash="0000000000000000000000000000000000000000000000000000000000000000"
```

The literals above are synthetic examples, not supplied assessment data. Hash/host/collection pivots keep each finding distinct. A shared hash is related evidence; multiple rule matches are not a count of compromised machines. `findings_for_hash` and `hosts_for_hash` are calculated across all current findings in this source before your pivot filter.

For the quality-attention view, insert:

```spl
| where quality_attention="review"
```

This includes current findings with one or more `quality_flags` and statuses outside the four documented values. Unknown statuses retain their original text. Quarantined rows were not sent to this index; inspect the importer's validation report for their original evidence and reasons. Indexed flags reflect the snapshot when that version was sent. The latest validation report remains authoritative for cross-record warnings.

## Verify ingestion separately from acceptance

A successful HEC response proves acceptance, not searchable indexing. Run this count check against the same explicit source and All time range:

```spl
index="volexity_lantern" source="lantern:assessment" sourcetype="lantern:indicator_match" earliest=0 latest=now
| spath
| stats count AS stored_events dc(id) AS distinct_findings dc(event_version) AS distinct_versions
```

Compare an export of these pairs with the importer's eligible preview; a matching total alone can conceal missing and unexpected events:

```spl
index="volexity_lantern" source="lantern:assessment" sourcetype="lantern:indicator_match" earliest=0 latest=now
| spath
| stats count AS stored_copies BY id event_version
| sort 0 +str(id), +str(event_version)
```

For replay verification, compare the counts and pair set before and after repeating the same import with the same ledger and destination profile. The importer should report previously accepted versions and no new sends. For lifecycle verification, use a separate synthetic source and show that a dated reviewed version replaces its initial UNREVIEWED baseline even though `_time` is unchanged and a stale version arrives later. Keep both versions visible in history.

These searches describe logical current state. They do not promise exactly-once storage, automatically retract historical identity conflicts, or repair source data.
