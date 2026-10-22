# Standalone native export: owner commissioning only, no restore/deletion

## Current owner checkpoint

### 22 October synthetic fixture repair (base bf94d5a)

Run 39711994101 failed before the first case because the exact pinned image
reports `pg_dump (PostgreSQL) 17.11 (Debian 17.11-1.pgdg12+2)`, while the fixture
compared it with the shorter upstream string. The exporter, requirements, image
digest, resource limits and workflow are unchanged. The corrected fixture
compares the complete exact packaged version; it does not accept another patch.
Fixed-label `failing_case` and numeric `fixture_exit_code` are now projected on
failure; raw native errors, SQL, identities and environment values stay hidden.
Independent review also found the old `! grep` assertions were exempt from Bash
errexit. Explicit branches now reject both a forbidden password match and grep
errors. Linux negative tests exercise clean, forbidden and missing-file cases.

The failed run is preserved. After exact-final-SHA Quality (both Python patches),
Resilience, CodeQL and code-scanning results pass and the owner merges the repair,
record the NEW full merged SHA. Do not rerun the old failed workflow. Dispatch
ONE new synthetic run on the repaired merged main with the confirmation ticked;
temporarily set ONLY LIVE_BACKUP_CONFORMANCE_ENABLED=true and remove it afterwards.
Require all ten cases and stopped-container verification, not just a green page.
Then use a fresh clean tools checkout at that same merged SHA: source binding,
fresh whole-profile audits, Windows directory drill, native tool/CA check, and
ONE opaque export alone in a quiet period. No private export before both native
gates pass. Any failure/unknown outcome stops the sequence for review.

Historical checkpoints below do not supersede this repair or its new SHA gate.

The38-file accepted repository main475185c1b54d78ca5be66bbe9f71bbd5888be868
and exact head9145fad CI are owner-reported green. Two-root preservation and
external extraction are owner-verified; native DATABASE backup acceptance is
still separate. No change to the exporter, conformance workflow, tool pins or
requirements is needed to begin its synthetic gates. This documentation/name-
guard maintenance must not become another delay for the accepted exporter.

Issue reference blocks below ONE at a time. Hosted Linux synthetic may run at
any time without private project data; Windows native/drill/live export require
a quiet period after capture/audit, not concurrently with Thursday's session.
Require SYNTHETIC_NATIVE_LOGICAL_RESTORE_PASSED with all ten cases true and
synthetic_container_stopped_verified=true. The synthetic container is retained
stopped until runner disposal, not deleted by this tool. An absent/skipped job
is not acceptance. Remove ONLY the
temporary conformance variable after its one dispatch, including failure.

After export, require a fresh hidden-prompt7-Zip test BEFORE copying/accepting
encryption. Use `7z t <new archive>` WITHOUT -p, password values or redirection;
creation success and ciphertext hash alone cannot prove password recoverability.
Then verify actual destination bytes/volume, full destination extraction and
trusted manifest anchor. No deletion follows any of these steps automatically.

STOP until the separate source repository's exact final SHA passes complete
Backup quality on both Python patches, CodeQL AND Code scanning results. The
owner merges and selects that externally reviewed merged SHA. No claim that
application PR56/57 or the affected application audit is green.

Immediately before commissioning a new real export, rerun the complete runtime
audit from the separate audited test/tool environment. New findings or lookup
failure block. Do not rely indefinitely on a historical green CI result or use
an image-format exposure assessment as a backup dependency-audit exception.

Use a NORMAL Windows PowerShell console, one block at a time, after capture and
audit are finished, explicit dedicated Python 3.13.9. Do not pipe or redirect a
confirmed native operation: native passwords are entered only into its console
prompt. Never put a password, URI, passfile or environment credential in argv.
No ACL, service, listener, clock, capture or journal change is required.

## 1. Source, runtime and independent synthetic acceptance

Create a new clean checkout at $backupReviewedSha and a separate --without-pip
runtime venv outside that checkout. Install the complete hashed runtime using
the reviewed bootstrap's pip --python <new interpreter> install
--require-hashes --only-binary=:all: -r requirements-runtime.txt. Pip check is
mandatory. Runtime must contain ONLY cryptography/cffi/pycparser/packaging at
their exact lock versions, not pip, pytest, Streamlit, Pillow or test libraries.
Use a DIFFERENT disposable test environment for the complete test lock/audit.

From the tools checkout, preview:

```powershell
$ErrorActionPreference='Stop'
& $backupRuntimePython -I -S -B .\standalone_backup_launch.py
if($LASTEXITCODE -ne 0){throw 'Preview rejected'}
```

Owner may temporarily set ONLY LIVE_BACKUP_CONFORMANCE_ENABLED=true in the NEW
repository and dispatch Disposable live logical backup conformance with the
confirmation ticked on the exact reviewed main. Remove that variable afterwards.
Require all ten synthetic native cases and synthetic_container_stopped_verified
true (stopped/retained, not deletion proof). It uses
only synthetic PostgreSQL in two fresh isolated clusters, no project secrets,
published ports, host PostgreSQL, private artifacts or scheduled runs.

Then owner chooses a NEW empty-path synthetic directory (do NOT pre-create it)
and runs once:

```powershell
$ErrorActionPreference='Stop'
& $backupRuntimePython -I -S -B .\standalone_backup_launch.py --reviewed-source $backupReviewedSha --operation backup --confirm-run --mode directory-drill --run-root $newSyntheticDrillRoot --confirm-no-capture-running
if($LASTEXITCODE -ne 0){throw 'Preserve drill outcome; no retry/reset'}
```

Require SYNTHETIC_WINDOWS_DIRECTORY_LOCK_PASSED, all file/root/ancestor lock
proofs true. Generic WinError 5 is NOT accepted as native sharing-denial proof.
Do not retry, move back or clean up failed artifacts to manufacture acceptance.

## 2. Native tools and CA, still no source connection

Use existing PostgreSQL 17.11 clients at the fixed Program Files path; do not
start or use the non-loopback local server. Establish approved SHA-256 hashes
of pg_dump.exe, pg_dumpall.exe and pg_restore.exe with local read-only hashing;
do not learn them implicitly during export. The tool version checks must all
say PostgreSQL 17.11. Use the owner's dashboard CA file (verify-full); no system
CA installation or TLS relaxation. Private paths/hashes remain local.

Set $pinPgDump/$pinPgDumpall/$pinPgRestore, $backupCaFile and the externally
reviewed source SHA yourself from their approved records. A tool hash is an
identity anchor, not a security audit of its linked native DLLs.

```powershell
$ErrorActionPreference='Stop'
& $backupRuntimePython -I -S -B .\standalone_backup_launch.py --reviewed-source $backupReviewedSha --operation backup --confirm-run --mode check-local --ca-file $backupCaFile --pin-pg-dump $pinPgDump --pin-pg-dumpall $pinPgDumpall --pin-pg-restore $pinPgRestore
if($LASTEXITCODE -ne 0){throw 'Native local admission failed; review'}
```

Require LOCAL_NATIVE_TOOLS_CHECKED_NOT_SOURCE_OR_RESTORE. This has not tested
the password, remote source connection, current capacity or completeness.

## 3. One explicitly approved opaque source export

Choose a NEW private output path outside tools and capture roots, with at least
32 GiB freshly measured free for the full preservation sequence. The unchanged
native code's 12 GiB minimum covers only that bounded operation, not encryption,
extraction, retained generations or an isolated restore. See README's capacity
plan; do not infer encrypted or restored size from the source database quota.
Do NOT pre-create it. Dumps can contain sensitive configuration and
data even though role passwords are excluded. Existing private ACLs are an
owner responsibility; this tool does not change or attest them.

Only if the owner now explicitly approves the live read operation, confirms no
capture running, accepts opaque preservation of sealed data without inspection,
and has personally verified the two native acceptance gates:

```powershell
$ErrorActionPreference='Stop'
& $backupRuntimePython -I -S -B .\standalone_backup_launch.py --reviewed-source $backupReviewedSha --operation backup --confirm-run --mode export --run-root $newPrivateBackupRoot --ca-file $backupCaFile --pin-pg-dump $pinPgDump --pin-pg-dumpall $pinPgDumpall --pin-pg-restore $pinPgRestore --confirm-no-capture-running --confirm-opaque-holdout-backup --confirm-native-acceptance
if($LASTEXITCODE -ne 0){throw 'Preserve partial attempt and review; no retry/reset'}
```

The source profile/endpoint is fixed in reviewed source. A native password prompt
appears for each required connection, not in Python output. Password failure,
permission failure, warnings, truncated streams, timeout or storage uncertainty
block; do not loosen exclusions, hide stderr or accept a partial subset.

Expected success is OPAQUE_LOGICAL_EXPORT_NOT_RESTORE. Preserve all five private
files: attempt.json, database.dump, roles.sql, toc.list, manifest.json. Never
upload them to source control or paste contents. A blocked/unknown attempt is
consumed and preserved; fresh attempt needs a separately reviewed decision.

The database MVCC dump and separate roles export do NOT share one atomic source
snapshot; this is not all Supabase platform configuration. Hashes and pg_restore
--list are not a typed restore or custody proof. Next: encrypt/preserve copies,
authenticated binding of A/B/new generation and access facts, then isolated typed
restore with version/conflict policy and cold-reader proof; retention LAST.

No missing historical evidence, source authenticity or trading eligibility is
created by an export. The original archive guards/deletion hold stay unchanged.

## 4. Data-only handoff, never an executable restore instruction

Preserve the original manifest bytes unchanged. BACKUP_ARTIFACT_INTERFACE.json
describes the boundary; backup_artifact_contract.py is a pure projection of
SUPPLIED measurements, not a file verifier or signed custody agent. The receiving
main-repo tooling must independently verify byte lengths and SHA-256, bind the
generation and reviewed producer commit to authenticated evidence, and enforce
its own conflict/restore gates without importing sibling Python code.

Before any target DDL, inventory its database-wide event triggers, platform
extensions and execution context. A pre-existing trigger can alter RLS while
tables are being restored; --disable-triggers is not an event-trigger guarantee.
The main local v2 access review is separate, uncommissioned work. Do not restore
into the existing non-loopback local PostgreSQL server, a serving project or a
target with unknown trigger behavior. No automatic trigger disabling or privilege
changes are authorized here. No deletion or cleanup follows a hash-equal export.
