# Decisions

| Decision | Rationale | Status |
|---|---|---|
| Local Splunk Enterprise | Native runtime and actual HTTPS ingestion/search were verified after Cloud provisioning delayed setup | Accepted |
| Python CLI; Splunk supplies analyst UI | Small, explainable integration and existing analyst workflow | Accepted |
| Custom sourcetype with selected CIM Alerts field meanings | Retain useful semantics without claiming full CIM or Enterprise Security compatibility | Accepted |
| Rule score and analyst disposition stay separate | A high-scoring match can be reviewed as benign | Accepted |
| Original match time is event time | Upload time is not detection time | Accepted |
| Preserve nested original record | Normalization remains inspectable; original bytes are kept separately | Accepted |
| Validate whole snapshot before delivery | Detect every member of conflicting identity groups before sending | Accepted |
| Quarantine unusable identities; warn on usable inconsistent evidence | Avoid invented data without hiding identifiable findings | Accepted |
| SQLite tracks pending and accepted versions | Repeatable imports without a separate database service; uncertainty stays explicit | Accepted |
| One event per request; single importer per ledger | Small dataset does not justify partial-batch complexity | Accepted |
| Public repo contains synthetic data only | Assessment inputs and live credentials stay in private submission materials | Accepted |
| Five severity bands | Prototype policy, not a vendor-mandated conversion; retain source score | Accepted |

Severity policy: 0–19 informational; 20–39 low; 40–69 medium; 70–89 high; 90–100 critical. Changes require a mapping-version change.

Delivery does not promise exactly-once storage. HEC acceptance is independently checked through Splunk search. Record implementation deviations below as they occur.

## Implementation details and deviations

- Use ordinary package installation, not editable installation, in reviewer instructions. The host marks generated editable `.pth` files hidden and Python 3.14 skips them. Development tests explicitly include `src`; clean installed-package verification remains required.
- Exit codes are 0 (clean completed), 2 (completed with warnings or quarantine), and 1 (operational failure). Duplicate input rows alone are informational.
- Input loading rejects duplicate JSON object keys, non-finite numbers, and invalid UTF-8 before sending any event. An unknown status remains literal and flagged.
- Every run has a manifest (`run-report.json`) listing artifacts produced by that run. This distinguishes current output from stale files if an operator reuses a directory.
- Live sending requires explicit configuration and ledger paths. Dry run has no credential, network, or ledger dependency.
- The local certificate compatibility profile retains chain and name checks and only applies to literal loopback plus an explicit CA. Remote endpoints use normal verification.

- Timestamp precision is limited to microseconds (up to six fractional digits). Higher precision is rejected explicitly rather than rounded into misleading equal timestamps.
- The detailed retrospective and test report distinguish HEC acceptance, automated transport tests, and independent Splunk indexing checks. A blocked browser check remains pending.
