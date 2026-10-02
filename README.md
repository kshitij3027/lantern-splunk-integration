# Lantern → Splunk prototype

A Python command-line importer turns a Lantern JSON export into searchable Splunk findings. It validates the whole snapshot, preserves original evidence, delivers eligible findings through HTTPS HEC, and remembers accepted source versions in a local SQLite ledger.

This is Scenario 1: a file-based prototype using Splunk's existing analyst interface. It does not fetch a Lantern API, run detection rules, or claim full CIM/Enterprise Security compatibility. The public sample is entirely synthetic. Supplied assessment inputs, tokens, local profiles, and generated evidence stay outside Git.

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

Implementation and live verification are recorded as they are completed. Detailed test evidence and the demo script are added at the final verification milestone. Trial cleanup is a post-delivery task, after preserving the submitted artifacts.
