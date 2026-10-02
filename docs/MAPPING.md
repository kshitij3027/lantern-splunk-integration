# Mapping contract, version 1

One eligible Lantern record becomes one HEC JSON event. An event is a match between a file and a rule on a host within a collection. It is not an entire collection, an incident, or an assertion that the endpoint is compromised. Lantern has already performed the matching.

## Envelope

| HEC property | Source or policy | Why |
|---|---|---|
| `time` | Epoch seconds parsed from `timestamp` | Original match time becomes Splunk `_time` |
| `host` | `host.hostname` | Endpoint context, not the importer machine |
| `index` | Configured dedicated index | Explicit destination |
| `source` | Configured export category | Separate assessment, synthetic, and setup datasets |
| `sourcetype` | `lantern:indicator_match` by default | Consistent JSON search scope |
| `event` | Normalized fields plus original `lantern` object | Searchable vocabulary with evidence preserved |

## Event fields

| Source | Normalized field(s) | Handling |
|---|---|---|
| `event_id` | `id` | Required finding identity; separate from revision identity |
| `event_type` | `lantern_event_type`; `type="event"` | Only `indicator_match` supported; retains source meaning separately |
| Product identity | `app="Lantern"` | Explicit source product |
| `host.hostname`, `host.host_id` | `dest`, `host_id` | Both required; stable ID is useful for pivots |
| `host.ip`, `host.os`, `host.agent_version` | `dest_ip`, `host_os`, `agent_version` | Optional context; invalid IP remains only in original evidence |
| `severity` | `severity_id`, `severity` | Original integer retained; five explicit prototype bands |
| `rule.name` | `signature` | Required matched rule name |
| `rule.namespace`, `.version`, `.author` | `rule_namespace`, `rule_version`, `rule_author` | Optional metadata; no invented rule ID |
| `file.path` | `file_path`, derived `file_name` | OS-aware Windows/POSIX basename; unknown OS omits derivation |
| `file.sha256` | `file_hash`, `file_hash_algorithm="sha256"` | Validate 64 hexadecimal characters; normalize hash casing only |
| `file.size` | `file_size` | Nonnegative integer; decimal string converts with a warning |
| `file.mtime`, `.owner` | `file_mtime`, `file_owner` | Preserve original timestamp text; not Splunk event time |
| `collection.collection_id` | `collection_id` | Correlates related findings; not finding identity |
| `collection.job_name`, `.requested_by`, `.completed_at` | `collection_job`, `collection_requested_by`, `collection_completed_at` | Preserve collection provenance |
| `matched_patterns` | `pattern_count`; full paired array inside `lantern.matched_patterns` | Do not flatten IDs and offsets into unrelated arrays |
| `disposition.status`, `.analyst`, `.comment`, `.updated_at` | `disposition_status`, `disposition_analyst`, `disposition_comment`, `disposition_updated_at` | Analyst judgment stays separate from rule severity |
| Parsed disposition time | `disposition_rank`, `disposition_time` | Undated baseline rank 0; dated revision rank 1, ordered numerically |
| Complete source record | `lantern` | Deep copy including unknown fields and original types/casing |
| Whole input file bytes | `source_sha256` | File provenance; whitespace changes this checksum |
| Original array position | `source_row` | One-based position for tracing reports to input |
| Canonical complete record | `event_version` | SHA-256 with sorted JSON keys and compact separators; independent of file formatting |
| Canonical record excluding disposition | `immutable_fingerprint` | Detect source evidence changes under an existing finding ID |
| Mapper policy | `mapping_version="1"` | Explicit version for field/normalization changes |
| Validator warnings | `quality_flags` | Stable reason codes; contextual to the snapshot when sent |

Null optional normalized values mean no trustworthy value was available, not deletion from the original. The assessment input file is kept unchanged separately; nested JSON retains values and structure, not original whitespace or key ordering.

## What does not fit cleanly

This uses selected Splunk CIM Alerts vocabulary as a mapping reference, not a complete CIM data-model implementation. The custom sourcetype does not install event types, tags, acceleration, or Enterprise Security notable-event behavior. Collection metadata, pattern offsets, rule versions, original numerical severity, and analyst dispositions retain explicit custom fields or nested evidence because forcing them into unrelated standard fields would change their meaning.

Severity is a mapping policy, not a Splunk-required conversion: 0–19 informational; 20–39 low; 40–69 medium; 70–89 high; 90–100 critical. A severity of 95 with a BENIGN disposition remains critical in severity and benign in judgment. It stays in searchable history while leaving the unreviewed queue.

An unknown disposition is preserved and flagged. It is not silently converted to UNREVIEWED. A missing timestamp is not replaced by import time. A conflicting finding ID is not resolved by keeping the first row. A shared hash is not collapsed into one finding or counted as confirmed compromise.

## Quality decisions

Required identity/evidence shape, finite JSON, valid timestamps, and supported event types are enforced. File modification must precede matching, which must not follow collection completion. A reviewed disposition cannot precede the match. Invalid essentials quarantine the original row. Immutable-ID and collection-completion conflicts quarantine every member of the conflicting group; tied contradictory disposition revisions are withheld.

Timestamps require calendar date, time through seconds, and an explicit `Z` or UTC offset. Fractional seconds may contain one through six digits. Higher precision is quarantined with an explicit `invalid_timestamp` explanation, never silently rounded or truncated into a different ordering.

Usable but questionable evidence receives warnings: lossless decimal-size conversion, missing optional context, unknown OS/status, invalid optional IP, empty pattern evidence, out-of-bounds offsets, and one hash associated with different sizes. Warnings can overlap. Reports count rows separately from individual issue occurrences.

Identical source rows in one snapshot are represented once after conflict checks. Across runs, the destination-scoped ledger skips only previously accepted versions. Changed disposition yields a new version without changing immutable evidence. A newly discovered cross-run identity conflict cannot remove earlier indexed events; it requires an operator/source correction workflow.
