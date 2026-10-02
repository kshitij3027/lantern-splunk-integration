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
