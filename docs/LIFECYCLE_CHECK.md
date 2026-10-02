# Reproduce the disposition lifecycle check

Use the three invented inputs in `examples/lifecycle` against a separate source such as `lantern:synthetic:lifecycle`. Copy your working local profile and change only `source`; retain verified TLS and token settings. Use one separate ledger for all three commands. Keep this source out of assessment searches.

1. Send `01-baseline.json`. Using a copy of the current-queue query with the lifecycle source, expect one high/critical UNREVIEWED finding, `synthetic-lifecycle-001`.
2. Send `02-newer-review.json`. Expect no current unreviewed finding. A current-state view without the status filter should show BENIGN; history should contain two versions.
3. Send `03-older-review.json`. This MALICIOUS review has an earlier revision time but arrives last. Expect the current state still to be BENIGN, no queue finding, and three history versions. All three share the original match `_time`.
4. Repeat any of the same sends with that ledger. Expect one previously accepted version, zero HTTP attempts, and unchanged indexed version/copy counts.

Example command (use a different report directory for each step):

```sh
lantern-splunk send --input examples/lifecycle/01-baseline.json --config local-lifecycle.toml --state output/lifecycle.sqlite --output output/lifecycle-1
```

Independent search expectations matter: successful HEC responses alone do not verify the query ordering. Keep screenshots/exported search results as private verification evidence. If testing again from scratch, choose a new deliberately isolated source and instance profile; do not delete or replace the assessment ledger to make its replay look like a first import.
