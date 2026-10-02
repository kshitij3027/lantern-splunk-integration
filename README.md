# Lantern → Splunk prototype

A Python command-line importer turns a Lantern JSON export into searchable Splunk findings. It validates the whole snapshot, preserves original evidence, delivers eligible findings through HTTPS HEC, and remembers accepted source versions in a local SQLite ledger.

This is Scenario 1: a file-based prototype using Splunk's existing analyst interface. It does not fetch a Lantern API, run detection rules, or claim full CIM/Enterprise Security compatibility. The public sample is entirely synthetic. Supplied assessment inputs, tokens, local profiles, and generated evidence stay outside Git.

## Approach

One eligible Lantern record becomes one Splunk event representing a rule match on a file, host, and collection. The importer validates the entire export before delivery so every member of an identity conflict is withheld. It quarantines unusable rows with their original evidence and reasons, maps eligible rows into searchable JSON fields, and sends them one at a time through verified HTTPS HEC. A local ledger records accepted source versions for repeat imports. Analysts then use Splunk searches for the current review queue, finding history, and related evidence; Lantern has already run the detection rules.

## Requirements and installation

- Python 3.11+ on macOS or Linux (ledger locking uses `fcntl`).
- For live delivery: Splunk Enterprise or Cloud with an HTTPS HTTP Event Collector endpoint, a dedicated event index, and a token permitted to write to that index.
- An authenticated Splunk browser session to verify indexing and investigate findings.

From the extracted project directory:

```sh
python3 -m venv .venv
source .venv/bin/activate
python -m pip install '.[test]'
python -m pytest -q
lantern-splunk --help
```

Use a normal package installation as shown. During development, pytest reads `src` directly; after code changes, reinstall before testing the installed command. No Docker, database server, or paid service is required by the importer. Splunk licensing is managed separately.

## First run, without Splunk

```sh
lantern-splunk validate --input examples/synthetic-events.json --output output/validate
lantern-splunk send --input examples/synthetic-events.json --dry-run --output output/preview
```

The synthetic sample yields **4 eligible findings: 3 clean and 1 warning**. Two are high/critical and UNREVIEWED. Both commands return **2**, indicating completed processing with quality issues; this is intentional. Dry run needs no token and neither contacts Splunk nor opens the ledger.

Each run prints its summary in the terminal. Reports in the output directory include:

| File | Purpose |
|---|---|
| `run-report.json` | Run status, source checksum, and list of artifacts produced by this run; consult this first if reusing a directory |
| `validation-report.txt` | Readable counts and row-level reasons |
| `validation-report.json` | Structured outcomes and original records for every input row |
| `quarantine.json` | Original unusable/conflicting rows and reasons; these are not sent |
| `mapped-events.jsonl` | Exact candidate HEC envelopes for `send`/dry run |
| `delivery-report.json` | Outcomes of attempted live delivery, separate from data quality |

Reports contain security evidence. Store them privately and use a separate output directory for each important run. They are operator artifacts, not an additional analyst dashboard. Input files are never modified.

Exit codes: **0** completed without warnings/quarantine; **2** completed with quality issues; **1** operational/input/configuration/delivery failure. Duplicate input rows are reported but do not alone cause exit 2. A mixed-quality file can send its eligible rows successfully and still return 2. A fatal document error sends nothing.

## Run the supplied assessment export from the reviewer ZIP

The private reviewer ZIP additionally includes the unchanged supplied `input/events.json` and `input/SCHEMA.md`. These files are excluded from the public repository. After the installation above, run from the extracted project directory:

```sh
lantern-splunk validate --input input/events.json --output output/assessment-validation
lantern-splunk send --input input/events.json --dry-run --output output/assessment-preview
```

Expected: **200 rows, 193 eligible (33 with warnings), and 7 quarantined**, with 24 high/critical UNREVIEWED queue candidates. Both commands return 2 because of the reported quality issues. The preview makes no network requests. For live delivery, prepare your own `local.toml` as described below, use source `lantern:assessment`, then run:

```sh
lantern-splunk send --input input/events.json --config local.toml --state output/assessment.sqlite --output output/assessment-import
lantern-splunk send --input input/events.json --config local.toml --state output/assessment.sqlite --output output/assessment-replay
```

In a fresh destination scope, expect 193 acceptances on the first send and 193 previously accepted versions with zero HTTP attempts on the repeat. Independently check Splunk indexing and the 24-row current queue as described in the investigation section; HEC acceptance alone does not prove indexing.

## Starting and stopping a local Splunk installation

Run these as the account that owns/runs your native installation, replacing the directory:

```sh
/path/to/splunk/bin/splunk start
/path/to/splunk/bin/splunk status
```

On first startup, complete Splunk's license/account prompts yourself, then sign into the local Web address shown by the command. Once your demo and verification are finished, stop that local process with `/path/to/splunk/bin/splunk stop`. Stopping a process does not cancel a Cloud subscription. Service-managed Linux installations should use their configured service manager instead. See Splunk's [first-start instructions](https://help.splunk.com/en/splunk-enterprise/get-started/install-and-upgrade/10.6/start-using-splunk-enterprise/start-splunk-enterprise-for-the-first-time) and [start/stop reference](https://help.splunk.com/en/splunk-enterprise/administer/admin-manual/10.0/start-splunk-enterprise-and-perform-initial-tasks/start-and-stop-splunk-enterprise).

## Configure and send

1. In Splunk, create an event index (the examples use `volexity_lantern`). Enable HTTPS HEC, create a dedicated token restricted to this index, and retain its certificate authority when using a private CA.
2. Copy `config.example.toml` to an ignored file such as `local.toml`. Set the actual HEC endpoint, index, source, and trust configuration. For the public synthetic sample, use `source = "lantern:synthetic"`. For the private assessment, use `source = "lantern:assessment"`.
3. Supply the token through `SPLUNK_HEC_TOKEN` or a private `token_file` referenced by the profile. Keep token files owner-only (`chmod 600`). Never place a token in command arguments or commit it. Relative file paths in the profile resolve beside that profile.
4. Run:

```sh
lantern-splunk send --input examples/synthetic-events.json --config local.toml --state output/delivery.sqlite --output output/import-1
lantern-splunk send --input examples/synthetic-events.json --config local.toml --state output/delivery.sqlite --output output/import-2
```

The first run should accept four events. The identical second run should report four previously accepted versions and **zero HTTP attempts**. Keep the same ledger for a destination; changing or losing it can resend events. Do not run two importers against the same ledger concurrently.

For the tested native local Splunk instance, HEC listens on `https://127.0.0.1:8088/services/collector/event`, whereas the browser uses `http://127.0.0.1:8000`. They are different interfaces. The default local certificate is CN-only: configure the installation's `cacert.pem` and its actual certificate name through `tls_server_name`. That compatibility setting is restricted to a literal loopback endpoint with an explicit CA; normal remote endpoints require standard certificate verification. There is no insecure-TLS switch. A reviewer can use their own already configured Splunk instance; no installation-specific paths or credentials are bundled.

## Investigate in Splunk

Select **All time** because `_time` is the original match time, not upload time. Follow [the investigation guide](docs/INVESTIGATION.md) to run/save the three searches in `splunk/searches`:

1. **Current review queue:** high/critical findings whose latest disposition is UNREVIEWED.
2. **Finding history:** original evidence and every distinct source revision.
3. **Related evidence and quality:** pivot by host, collection, or file hash and inspect warnings.

Each search explicitly scopes index, source, and sourcetype. Change its source to `lantern:synthetic` when using the public sample. A HEC success is acceptance, not proof of indexing: verify the searchable ID/version set independently. Rule matching already happened in Lantern. These searches retrieve existing matches and related evidence.

## Mapping and quality policy

`timestamp` becomes HEC `time`; host hostname becomes `host` and `dest`; rule name becomes `signature`; source score remains `severity_id`. Severity bands are a prototype policy: 0–19 informational, 20–39 low, 40–69 medium, 70–89 high, 90–100 critical. Analyst disposition remains independent of severity. File/hash, collection, rule, host, pattern, and review context are retained. Every event includes a nested `lantern` copy of the original record, source SHA-256, one-based source row, mapping version, and quality flags.

Whole-snapshot validation catches missing essentials, invalid types/times, immutable ID collisions, collection completion conflicts, and ambiguous tied revisions before sending. Decimal size strings can be converted losslessly with a warning; unknown statuses, empty pattern lists, out-of-bounds offsets, and inconsistent hash/size evidence remain inspectable with warnings. No missing identity or evidence is invented. See the [complete mapping contract](docs/MAPPING.md), [decisions](docs/DECISIONS.md), and tests for precise boundaries.

## Fields that do not map cleanly

Selected Splunk CIM Alerts names provide useful vocabulary, but this prototype does not install a complete CIM data model or create Enterprise Security notable events. The following source concepts retain explicit custom fields or nested evidence instead of being forced into unrelated standard fields:

| Lantern concept | Decision and reason |
|---|---|
| Numerical severity | Keep the original score in `severity_id`; derive `severity` using the documented prototype bands. These bands are a product policy, not a required Splunk conversion. |
| Analyst disposition, analyst, comment, and update time | Preserve dedicated `disposition_*` fields. Analyst judgment and review history are independent of rule severity and event match time. |
| Collection ID, job, requester, and completion time | Keep `collection_*` provenance fields. A collection groups findings; it is not a finding identity or an incident. |
| Rule namespace, version, and author | Keep `rule_*` metadata alongside the mapped `signature`; no absent standard rule ID is invented. |
| Matched pattern IDs and byte offsets | Preserve each ID/offset pair in `lantern.matched_patterns` and expose `pattern_count`. Separate flattened arrays could lose the pair relationship. |
| Unknown fields and questionable evidence | Retain the complete `lantern` record and explicit `quality_flags`; preserve unknown dispositions rather than converting them to UNREVIEWED. |

The [complete mapping table and boundary rules](docs/MAPPING.md) cover every source field, and the [decision record](docs/DECISIONS.md) explains the tradeoffs.

## Delivery and revision behavior

A canonical source-record hash identifies each version. The source excluding disposition identifies immutable evidence. The ledger scope includes destination endpoint, index, source, sourcetype, mapping version, and configured instance ID; tokens are excluded so token rotation does not force a resend. Change `instance_id` deliberately if replacing a Splunk instance at the same address.

Each request gets a durable pending ledger entry before network activity. Acceptance requires a successful HTTP status **and HEC code 0**. Authentication and configuration failures stop the run. Transient errors have at most three attempts. Lost responses and interrupted pending attempts remain **uncertain**, with possible duplicates explicitly reported. Redirects and library-level retries are disabled. This is not an exactly-once storage guarantee.

Disposition updates create new searchable versions. Searches choose a complete row using disposition rank/time, then filter the current status. `_time` remains the match time and cannot order review changes. Older revisions cannot replace newer ones merely by arriving later. Conflicting immutable evidence or tied disposition revisions require investigation; this prototype cannot retract evidence already indexed in an earlier run.

Indexed quality flags describe the snapshot when a version was sent. The latest validation report is authoritative for later cross-record warning changes; unchanged source versions are not resent just to refresh flags.

## Project records

- [Approved plan](docs/PLAN.md)
- [Decisions and tradeoffs](docs/DECISIONS.md)
- [Implementation checkpoints](docs/BUILD_LOG.md)
- [Analyst investigation guide](docs/INVESTIGATION.md)
- [Synthetic lifecycle verification](docs/LIFECYCLE_CHECK.md)
- [Detailed test cases](docs/TEST_CASES.txt)
- [Timed narration and screen actions](docs/DEMO_SCRIPT.md)
- [Living post-mortem](docs/POST_MORTEM.md)

Implementation, all 279 automated cases, and the independent live Splunk checks are complete. The user has supplied a recording uploaded to Google Drive; its content, duration, playback, and recipient access have not yet been independently verified. The reviewer ZIP is being refreshed from committed source. Trial cleanup remains a post-delivery task, after preserving the submitted artifacts.
