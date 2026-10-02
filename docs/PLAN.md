# Approved implementation plan

Approved October 1, 2026. Scope: a file-based Lantern export integration with real Splunk, not a live Lantern API or Enterprise Security application.

1. Create public remote; initialize isolated local repository; connect them. Complete.
2. Prove the Python HTTPS client against the verified local Splunk instance, retaining certificate and hostname validation.
3. Build whole-snapshot validation and deterministic mapping; preserve original records. Test types, timestamps, severity bands, collisions, revisions, and evidence warnings.
4. Add sequential HEC delivery and a local SQLite attempt/acceptance ledger. Distinguish acceptance from indexing and uncertain delivery from rejection.
5. Integrate a CLI for validation, dry run, and send. Produce readable and structured quality reports.
6. Verify real ingestion and exact finding identities in Splunk; verify repeat imports and latest-disposition searches.
7. Test failures and clean-environment reproduction. Create a detailed plain-text test-case report.
8. Finish README, mapping decisions, demo narration/action script, and post-mortem. Record an end-to-end walkthrough using the user's selected recording tool.
9. Package the reviewer ZIP separately from the public repository. The ZIP may include the supplied input; public fixtures remain synthetic.
10. Rehearse the narrated final video and verify recipient access before final handoff. Clean up local/Cloud trials only after completed delivery.

## Definition of done

All input rows are accounted for; originals remain unchanged; eligible findings appear in real Splunk; reruns skip accepted versions; changes to disposition select the correct complete current row; errors and uncertainty remain visible. Tests and fresh-environment instructions pass. No secret or proprietary input is published. Working changes are committed and pushed at meaningful milestones.

## Priorities

Core: correct mapping, quality handling, real ingestion, replay behavior, tests, documentation, video. Optional: dashboard polish. Production follow-up: API retrieval/cursors, durable queuing, stronger delivery guarantees, customer-approved severity and CIM semantics, conflict correction workflows.
