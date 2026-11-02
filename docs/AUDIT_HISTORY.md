# SQLite audit history (Stage 5)

An optional, local, append-only record of classification runs. It is **off by default**.
It never changes a label, a reason code or any evidence, and the classification path never
reads it.

## Turning it on and off

| Way | Effect |
|-----|--------|
| nothing set | Stage 4 behaviour. No database is created, nothing is written. |
| `NETCLASS_AUDIT_ENABLED=true` in `.env` | `classify_ip.py` saves every run. |
| `classify_ip.py IP --audit` | Saves this run only. |
| `classify_ip.py IP --no-audit` | Does not save, even if the setting is on. |
| Python: `service.classify_and_record(obs)` | Classifies, then saves (needs an `AuditStore`; `from_settings` builds one only when `audit_enabled`). |
| Python: `service.classify(obs)` | **Never writes**, whatever is configured. |

The database path is `NETCLASS_DB_PATH` (default `data/audit.sqlite3`, git-ignored). The file is
created on the first successful save, not before.

## What a failed save looks like

The classification is always returned. `classify_and_record` returns an `AuditedResult` with
`audit.status`:

* `SAVED`: the transaction committed (`run_id`, `recorded_at` are set).
* `FAILED`: nothing was saved; `error` is a short redacted description; a warning is logged.
* `DISABLED`: no store was configured; nothing was written.

`classify_ip.py --audit` prints an `"audit"` section, and when the save did not happen it prints
`WARNING: ... NOT saved` on stderr and exits **5** (the result JSON is still printed). With
auditing off, output and exit codes are identical to Stage 4.

## Schema (version 1)

* `schema_migrations(version, description, applied_at)`; also `PRAGMA user_version` and
  `PRAGMA application_id` (marks the file as an audit database).
* `classification_runs`: one row per run: `recorded_at`, `observed_at`, `ip`, `label`,
  `reason_code`, `additional_reason_codes`, `explanation`, `caveats`, `policy_version`,
  `service_version`, `ripestat_requested`, `ipinfo_requested`, `redaction_count`, `result_json`
  (the full classification result). CHECK constraints limit `label` and `reason_code` to the
  existing values.
* `evidence_records`: the classifier's evidence only (source, kind, status, hashes, provenance,
  applicability and note). **No RIPEstat or IPinfo data.**
* `context_metadata`: RIPEstat / IPinfo supplementary metadata only (`provider`, `status`,
  `payload_json`). Present only when that lookup was requested.
* Triggers make all three tables append-only (UPDATE is refused; INSERT and DELETE are allowed).
  Deleting a run cascades to its evidence and metadata.

`result_json` includes the classification's existing display-only `network_context` field
(Stage 3B), because it is part of the Stage 4 result; it is not evidence and is not stored in
`evidence_records`.

### Migrations and refusals

Migrations are numbered and applied one per transaction. A write upgrades an older audit
database; a read never modifies. The store **refuses, and leaves untouched**: a database newer
than the code, a SQLite file of another application, and a file that is not SQLite. It never
truncates, replaces or overwrites an existing file; a new file is created exclusively.

## Privacy

* The database stores IP addresses you classify, observation times, labels, reason codes and
  evidence records. IP addresses can be personal data; treat the file accordingly.
* **Never stored:** the IPinfo token or any configured secret, `Authorization` headers, cookies,
  and raw HTTP response bodies. Secret-shaped values are replaced by `[REDACTED]`; body-like
  fields are replaced by a marker; `redaction_count` records how many changes were made. IPinfo
  and RIPEstat are stored as parsed models plus the response SHA-256, never as raw bodies.
* Logs contain only a short redacted error description, never record contents.
* Permissions: on POSIX the file is created `0600` and a newly created directory `0700`. An
  existing file is not changed, but a warning is logged if it is readable by others. On Windows
  these modes are not applied; use a user-private folder (your profile / project folder).
* Not encrypted. Anyone who can read the file can read the history.

## Retention (explicit only)

`NETCLASS_AUDIT_RETENTION_DAYS` (default **90**) is applied **only** when you run
`python scripts\audit_history.py purge --yes`. Nothing purges on start-up, when a database is
opened, when a record is saved, or on a schedule. `purge` without `--yes` is a dry run.
`0` means keep indefinitely: `purge` then deletes nothing (use `purge --days N` to override once).
Keeping records indefinitely means IP-address history accumulates until you delete it yourself.
Purge works on when a record was **saved**, not on the observation time, and uses
`secure_delete`; add `--vacuum` to also shrink the file. Copies you make of the file (backups,
exports) are not purged.

## Commands

```powershell
python scripts\audit_history.py info
python scripts\audit_history.py list --ip 8.8.8.8 --limit 20
python scripts\audit_history.py show 3
python scripts\audit_history.py export --output history.json     # refuses to overwrite
python scripts\audit_history.py purge                            # dry run
python scripts\audit_history.py purge --yes --vacuum             # delete runs older than retention
python scripts\audit_history.py delete-ip 8.8.8.8 --yes          # erase one address (dry run without --yes)
```

Exit codes: 0 ok, 1 database problem, 2 invalid arguments.

## What it does not do

No dashboard (Stage 6), no encryption, no remote storage, no automatic cleanup, no use of history
for classification, no deduplication (every call is its own row).
