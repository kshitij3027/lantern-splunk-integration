"""Small operator interface: validate, preview, or deliver a complete export."""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import sys

from .config import ConfigError, load_config
from .delivery import deliver
from .mapping import MAPPING_VERSION, map_record
from .reporting import write_json, write_preview, write_validation
from .state import DeliveryScope, StateError, StateStore
from .transport import HECClient, TransportConfigurationError
from .validation import DocumentError, validate_document


class Parser(argparse.ArgumentParser):
    def error(self, message):
        self.print_usage(sys.stderr)
        self.exit(1, f"error: {message}\n")


def _object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise DocumentError("Duplicate JSON object keys are ambiguous; input was not processed.")
        result[key] = value
    return result


def _constant(_value):
    raise DocumentError("Non-finite JSON numbers are not supported.")


def read_input(path: Path):
    try:
        raw = path.read_bytes()
        data = json.loads(raw.decode("utf-8-sig"), object_pairs_hook=_object, parse_constant=_constant)
    except (OSError, UnicodeError, json.JSONDecodeError, RecursionError) as exc:
        raise DocumentError("Cannot read a valid UTF-8 JSON document; no events were sent.") from exc
    return data, hashlib.sha256(raw).hexdigest()


def parser():
    root = Parser(description="Validate Lantern exports and deliver eligible findings to Splunk.")
    root.add_argument("--version", action="version", version="lantern-splunk 0.1.0")
    sub = root.add_subparsers(dest="command", required=True)
    for command in ("validate", "send"):
        child = sub.add_parser(command)
        child.add_argument("--input", required=True, type=Path, help="Lantern JSON array file")
        child.add_argument("--output", required=True, type=Path, help="Directory for this run's private reports")
        child.add_argument("--config", type=Path, help="TOML destination profile; required for a live send")
        if command == "send":
            child.add_argument("--dry-run", action="store_true", help="Write mapped JSONL without network or ledger access")
            child.add_argument("--state", type=Path, help="Persistent SQLite ledger; required for a live send")
    return root


def main(argv=None):
    args = parser().parse_args(argv)
    live = args.command == "send" and not args.dry_run
    if live and (args.config is None or args.state is None):
        print("error: live send requires both --config and --state.", file=sys.stderr)
        return 1
    outdir = args.output.expanduser().resolve()
    generated = {outdir / name for name in ("run-report.json", "validation-report.json", "validation-report.txt", "quarantine.json", "mapped-events.jsonl", "delivery-report.json")}
    protected = {p.expanduser().resolve() for p in (args.input, args.config, getattr(args, "state", None)) if p is not None}
    if generated & protected:
        print("error: report files would overwrite an input, configuration, or ledger; choose another output directory.", file=sys.stderr)
        return 1
    # Resolve secret/trust paths before writing even the run manifest.
    try:
        config = load_config(args.config)
    except ConfigError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    protected.update(Path(p).expanduser().resolve() for p in (config.token_file, config.ca_file) if p)
    if generated & protected:
        print("error: report files would overwrite a credential or trust file; choose another output directory.", file=sys.stderr)
        return 1
    run = {"started_at": datetime.now(timezone.utc).isoformat(), "command": args.command,
           "dry_run": not live, "status": "started", "artifacts": []}
    try:
        write_json(outdir / "run-report.json", run)
        data, checksum = read_input(args.input.expanduser())
        result = validate_document(data, checksum)
        write_validation(result, outdir)
        run["artifacts"].extend(["validation-report.json", "validation-report.txt", "quarantine.json"])
        counts = result.summary
        print(f"Validation: {counts['total']} rows; {counts['eligible']} eligible "
              f"({counts['eligible_with_warnings']} with warnings); {counts['quarantined']} quarantined; "
              f"{counts['duplicate']} duplicate input rows.")
        quality = bool(counts["quarantined"] or counts["warning_rows"])
        exit_code = 2 if quality else 0
        if args.command == "send":
            envelopes = [map_record(row, checksum, config.index, config.source, config.sourcetype)
                         for row in result.rows if row.status == "eligible"]
            write_preview(envelopes, outdir)
            run["artifacts"].append("mapped-events.jsonl")
            if args.dry_run:
                print(f"Dry run: {len(envelopes)} candidate events; no network requests or ledger changes.")
            elif envelopes:
                scope = DeliveryScope(config.endpoint, config.index, config.source, config.sourcetype,
                                      MAPPING_VERSION, config.instance_id)
                with HECClient(config.endpoint, config.load_token(), config.ca_file, config.tls_server_name,
                               config.connect_timeout, config.read_timeout) as client:
                    with StateStore(args.state, scope) as state:
                        report = deliver(envelopes, client, state, max_attempts=config.max_attempts)
                write_json(outdir / "delivery-report.json", report.to_dict())
                run["artifacts"].append("delivery-report.json")
                c = report.counts
                print(f"Delivery: {c['accepted']} HEC accepted; {c['previously_accepted']} previously accepted; "
                      f"{c['rejected']} rejected; {c['uncertain']} uncertain; {c['not_attempted']} not attempted. "
                      f"{report.attempts} HTTP attempts.")
                if any(record.possible_duplicate for record in report.records):
                    print("Warning: an earlier response was uncertain; possible duplicate events may exist in Splunk.")
                if report.has_failures:
                    exit_code = 1
                print("HEC acceptance must be checked independently in Splunk search.")
            else:
                print("Delivery: no eligible events; no network requests or ledger changes.")
        run.update(status="operational_failure" if exit_code == 1 else "completed_with_quality_issues" if quality else "completed",
                   exit_code=exit_code, source_sha256=checksum, completed_at=datetime.now(timezone.utc).isoformat())
        write_json(outdir / "run-report.json", run)
        print(f"Reports: {outdir}")
        return exit_code
    except (ConfigError, DocumentError, TransportConfigurationError, StateError, OSError, ValueError) as exc:
        # Config/validation/transport/state errors use safe messages. OS failures may
        # contain local paths, so return a fixed message for those.
        message = "A local file operation failed; check paths and permissions." if isinstance(exc, OSError) else str(exc)
    except KeyboardInterrupt:
        message = "Interrupted. A pending ledger attempt may be uncertain; inspect the next run before assuming delivery."
    run.update(status="operational_failure", exit_code=1, error=message)
    try:
        write_json(outdir / "run-report.json", run)
    except OSError:
        pass
    print(f"error: {message}", file=sys.stderr)
    return 1
