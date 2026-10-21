# Wednesday preservation and first live database backup: owner-controlled gates

## Superseding owner checkpoint after PR2 (22Oct follow-through)

Separate safety finding: the frozen application capture125153... operational
profile still declares certifi2026.7.22, affected by critical
GHSA-6q48-6c7w-9gw2. Do not create/run a capsule using those known affected pins;
new reviewed capture-profile release required, not an in-place upgrade. No
installed capsule was inspected here. The four-package backup RUNTIME contains
no certifi; its separate tool/test lock pins patched certifi2026.10.19. Neither
profile is blocked by that separate application issue on the audit evidence.

Owner reports accepted main475185c1b54d78ca5be66bbe9f71bbd5888be868, exact head
9145fad hosted328/3 on both Python patches and audits green. Both roots have
been preserved/verified:1106files10651004bytes. Good encrypted external USB copy
passed native destination/hash checks and extraction+full anchored verification.
These are OWNER-VERIFIED reports, not builder private access, signed custody,
database integrity or typed restore. The earlier instruction to preserve before
Thursday Prepare is satisfied as reported; do not repeat or overwrite that cut.
All12 old tasks were disabled by owner, not by this tooling.

For the next7-path SAME-SCOPE maintenance use ordinary
`standalone_backup_contract.py --check-update --base 475185c1b54d78ca5be66bbe9f71bbd5888be868`,
not the historical30->38 migration checker
below. Existing38-file scope/locks/native exporter/workflows stay unchanged.
No new package is a dependency for Thursday's installed manual capture or for
native acceptance of the accepted backup release.

### Mandatory independent password/readback check for FUTURE generations

Prefer7-Zip GUI format7z/AES-256/Encrypt file names, Show password OFF, both
password confirmation fields. Creation success alone never counts. Immediately
run a full separately prompted test, then destination extraction/manifest proof:

```powershell
$ErrorActionPreference='Stop'
& 'C:\Program Files\7-Zip\7z.exe' t $newEncryptedArchive
if($LASTEXITCODE -ne 0){throw 'Archive not accepted; preserve outcome and originals'}
```

No -p on this t command, no password on argv/environment, no redirection or
transcript. The reported first failure does not establish universal bare-p
behavior across every version. The good replacement must pass the same full
path as any new generation. First failed ciphertext, plaintext cut and extract
are NOT deleted automatically. Before reviewing cleanup, record exact private
identities/generation hashes and ensure retained independently recoverable
copies; original mutable roots are never cleanup targets. Second independent
location and authenticated custody remain open, even after a USB hash match.

Name-only reserved credential denial is now additional defense in depth at the
public source gate, including nested/case variants and suffix backups. Exact
allowlist/hash/index/final-SHA checks remain mandatory. No absolute guarantee
against renamed secrets or manual bypass is claimed. No hook/settings change.

## Historical initial extension instructions (not a second upload/copy request)

Source-only maintenance package for trading-backup-tools, exact base
70629fcc2a98814d6e0d8ea760ba27b70e5c819b. Nothing below commissions a copy,
enables a task/workflow, changes an ACL, restores a database or permits deletion.
Issue/run ONE block at a time in normal PowerShell; keep private paths, manifests
and evidence OUT of Git, Actions artifacts, issue bodies and chat.

## Current facts and the two independent lanes

Owner-reported DONE: public repository created; c311e08 had both Python quality
checks (225 passed on Linux), synthetic resilience and CodeQL green; main is the
exact base above. protect-main is active with PRs, zero required approvals,
four required checks, High-or-higher CodeQL results and deletion/force-push
protection. Dependency graph, Dependabot alerts, secret scanning and push
protection are on. Do NOT ask the owner to configure those again or silently
weaken them. These are owner-reported settings, not an independent settings audit.
The builder read the public exact-base manifest and cloned the public base;
neither operation changed GitHub. New package CI is still required.

Owner-reported Wednesday capture: 75/75, scheduled poll/audit result0, saved
audit at15:40:26. This is not authenticated journal/remote-custody proof. It meets
the post-capture TIMING prerequisite for synthetic backup acceptance. Actual
backup native acceptance is not yet run. Both private roots have no off-PC copy.

Lane1, urgent before Thursday Prepare/Start: preserve BOTH quiescent roots,
verify retained bytes, encrypt and verify copies off-PC. Lane2 can proceed on
the ALREADY accepted backup release independently: fresh dedicated runtime,
manual Linux synthetic, Windows directory drill, local tools/CA check, then
ONE separately approved opaque live export. Do not delay the accepted backup
route waiting for this optional preservation extension or the app's Pillow fix.

## First owner block: read-only readiness, no new code or private-file reads

This queries only public-named task METADATA and existence of the two roots.
It does not export task XML/arguments, read journal/config contents, stop a
process, disable anything or establish exclusive quiescence.

```powershell
$ErrorActionPreference='Stop'
$tasks=@(Get-ScheduledTask -TaskPath '\' -TaskName 'KiranTrading-*' -ErrorAction Stop |
    Where-Object {$_.TaskName -match '^KiranTrading-(Forward-(prepare|poll|audit)|Versioned-[0-9]{8}-(poll|audit))$'})
if($tasks.Count -lt 2 -or $tasks.Count -gt 64){throw 'Task inventory missing or exceeds reviewed bound'}
$base=Join-Path $env:LOCALAPPDATA 'KiranTrading'
[pscustomobject]@{
    status='READ_ONLY_CAPTURE_READINESS_NOT_COPY_ADMISSION'
    forward_exists=(Test-Path -LiteralPath (Join-Path $base 'Forward') -PathType Container)
    operations_exists=(Test-Path -LiteralPath (Join-Path $base 'ForwardOps') -PathType Container)
    task_count=$tasks.Count
    running_count=@($tasks | Where-Object {$_.State -eq 'Running'}).Count
    enabled_count=@($tasks | Where-Object {$_.Settings.Enabled -eq $true}).Count
    task_mutations=0;private_file_reads=0;writes=0
}|ConvertTo-Json -Compress
```

Share only that JSON. Do not infer no writer solely from running_count=0;
manually launched commands and other processes may still hold the files. After
review, the owner must ensure all writers remain stopped/disabled THROUGHOUT
copy and verification. No process is killed and no task is changed by the tool.
Do not run Thursday Prepare/Start against the mutable roots until this cut is
preserved and verified. If the work cannot finish within the unchanged morning
deadlines, it is NO_GO without backfill, not permission to bypass a capture gate.

## Public package: one PR, explicit scope extension, no old-pin relaxation

Old distribution has30 files, new distribution38. The original inert-seed and
ordinary maintenance gates intentionally reject that scope change. Use ONLY
capture_preservation_upload_check.py for this one transition: it pins exact
base70629fcc..., the old complete manifest SHA-256
ae48c936dd642db90f91f0e32e030f3802fa06124fe3ce96f58d1ffc6d9d50a1,
every old committed payload/mode/path, all unchanged old index/worktree bytes,
the exact13 changed paths and the complete new distribution. The published DB
artifact interface, runtime/test locks, native exporter, native conformance,
vendored signing helpers and workflows stay UNCHANGED.

After this merge, ordinary same-scope --check-update works again against the
externally approved new release. No arbitrary newer base is accepted for THIS
migration. A changed head requires review/repackaging, not substituting a SHA.

Exact changed source -> target list (all other target files are prerequisites):

- capture_roots_preserve.py -> capture_roots_preserve.py (add)
- tests/test_capture_roots_preserve.py -> tests/test_capture_roots_preserve.py (add)
- backup_capacity_assessment.py -> backup_capacity_assessment.py (add)
- tests/test_backup_capacity_assessment.py -> tests/test_backup_capacity_assessment.py (add)
- sql/backup_capacity_sample_read_only.sql -> sql/backup_capacity_sample_read_only.sql (add)
- capture_preservation_upload_check.py -> capture_preservation_upload_check.py (add)
- tests/test_capture_preservation_upload_check.py -> tests/test_capture_preservation_upload_check.py (add)
- CAPTURE_PRESERVATION_2026-10-21.md -> CAPTURE_PRESERVATION.md (add)
- standalone_backup_contract.py -> standalone_backup_contract.py (modify)
- standalone_backup_launch.py -> standalone_backup_launch.py (modify)
- BACKUP_DELIVERY_DECISION_2026-10-21.md -> README.md (modify)
- BACKUP_DELIVERY_VERIFICATION_2026-10-21.md -> VERIFICATION.md (modify)
- generated BACKUP_TOOL_DISTRIBUTION.json -> BACKUP_TOOL_DISTRIBUTION.json (modify)

BACKUP_STANDALONE_UPLOAD.json is the source/export manifest, NOT a target file.
CAPTURE_PRESERVATION_UPLOAD_2026-10-21.json is the local owner upload list, NOT a
target file. Neither belongs in the reviewed target index. Export to a NEW
public directory, preserve earlier exports, and copy only the13 listed changes
into a NEW clean target clone at the exact base, core.autocrlf=false. No new
branch settings, actions, credentials, requirements or installed capsule changes.

Pre-commit checker (explicit existing3.13.9 test Python, not a bare py):

```powershell
& $python3139 -B capture_preservation_upload_check.py --base 70629fcc2a98814d6e0d8ea760ba27b70e5c819b
if($LASTEXITCODE -ne 0){throw 'Preserve staged state; review migration rejection'}
```

Full bundled/focused tests from the clean target, with the NEW dedicated audited
test environment OUTSIDE that checkout, not the four-package runtime:

```powershell
$ErrorActionPreference='Stop'
$tests=Join-Path $env:TEMP ('capture-backup-tests-'+[guid]::NewGuid().ToString('N'))
& $backupTestPython -B -m pytest -q -rs -p no:cacheprovider --basetemp $tests
if($LASTEXITCODE -ne 0){throw 'Bundled tests failed'}
$files=@(Get-ChildItem -LiteralPath . -File -Filter '*.py' | ForEach-Object {$_.Name})
& $backupTestPython -B -m pyflakes @files tests
if($LASTEXITCODE -ne 0){throw 'Lint failed'}
& $backupTestPython -B -m pip check
if($LASTEXITCODE -ne 0){throw 'Dependency graph failed'}
& $backupTestPython -B -m pip_audit -r requirements-runtime.txt
if($LASTEXITCODE -ne 0){throw 'Complete runtime audit failed'}
& $backupTestPython -B -m pip_audit
if($LASTEXITCODE -ne 0){throw 'Complete tool/test audit failed'}
git diff --cached --check
if($LASTEXITCODE -ne 0){throw 'Whitespace failed'}
```

Check repo-local identity presence before committing. Owner alone commits,
opens one plain-line PR and merges after exact-final-SHA required checks and
CodeQL/scanning results pass. No attribution/trailers. A Linux pass is not native
Windows acceptance: the new two-root native Windows tests must pass on the
owner's normal session using only disposable fixtures outside the code tree.
The optional SQL PGlite fixture is clearly skipped if absent; it is not native
Postgres permission/size acceptance. No install or privilege workaround to hide
a failed native test. The old Linux shell/symlink skips remain explicit.

## Two-root procedure after exact-SHA acceptance (reference, not batch permission)

Use a clean merged target checkout and the dedicated four-package runtime.
The launcher gains --operation preserve; every confirmed private command checks
the externally reviewed final source SHA before reading private state. It does
not import the main repo, installed capsule or producer modules. This is a new
root-scope tool, NOT a widening of forward_evidence_preserve.py's selected-session
allowlist. That older helper and its hashes remain untouched.

The sources are FIXED: the current user's LocalAppData/KiranTrading/Forward and
ForwardOps. Every directory and default file stream is inventoried, including
older dates, empty files/directories, recipes, ops reports, sidecars and locks.
No JSON research row, SQLite query, Python script, journal recovery or credential
store is opened for interpretation. Merely copying bytes does not examine sealed
2025/2026 data. Private configuration bytes can exist in an opaque copy: encrypt
before leaving the private local location; never upload a plaintext copy.
The supplied session date labels the owner's observation cut, not a verified
claim that every file/row belongs to that session or one atomic instant.

First run the preview. After writer/task readiness and explicit owner attestation,
inspect both roots once; it reports only counts/size/sidecar-name/lock-name counts.
Inspection does NOT prove a lock file is stale or that SQLite is consistent.

```powershell
& $backupRuntimePython -I -S -B .\standalone_backup_launch.py --operation preserve --reviewed-source $preservationReviewedSha --confirm-run --mode inspect --session-date 2026-10-21 --confirm-no-writers
```

Only after reviewing its result choose a NEW destination OUTSIDE both sources
and the code tree. Recommended parent: the already existing private
LocalAppData/KiranTrading directory, with a NEW sibling such as
CapturePreserved-20261021-<unique>. Do not pre-create the leaf. Its existing ACL
must pass read-only verification; no permission change, elevation or fallback.
Choose a different existing private parent if needed, after reviewing the cause.
Check free space: at least twice measured source bytes plus1GiB for this bounded
copy/encryption lane; actual encryption and restore budgets need fresh checks.

```powershell
& $backupRuntimePython -I -S -B .\standalone_backup_launch.py --operation preserve --reviewed-source $preservationReviewedSha --confirm-run --mode preserve --session-date 2026-10-21 --destination $newCapturePreservation --confirm-no-writers
```

Expected CAPTURE_TWO_ROOTS_OPAQUE_COPY_VERIFIED_NOT_CUSTODY. Record the returned
manifest_sha256 privately. Re-read that exact copy independently, without source
reads, supplying that external digest (do not discover it anew from a suspect copy):

```powershell
& $backupRuntimePython -I -S -B .\standalone_backup_launch.py --operation preserve --reviewed-source $preservationReviewedSha --confirm-run --mode verify --destination $newCapturePreservation --expected-manifest-sha256 $captureManifestAnchor
```

Expected CAPTURE_COPY_BYTES_VERIFIED_NOT_CUSTODY. During copy the tool denies
write/delete sharing on existing source file handles, pins directories against
deletion, and compares all inventories and bytes before/copy/after. It does NOT
claim an atomic volume snapshot or defend hostile same-user filesystem attacks.
All writers must remain quiescent. No task is disabled/enabled by this tool.
Source access times may be affected by the OS; no source write commands or data/
mtime changes are requested. Any block/unknown leaves partial output intact and
no successful completion manifest; do not reset, overwrite or retry blindly.

This is both roots' DEFAULT STREAMS, NOT a full PC image. ACLs/alternate streams,
scheduled task registrations, external credentials/keys, services and the
installed capsule are NOT restored by it. SQLite WAL/SHM/journal/lock files are
copied as opaque evidence rather than deleted or checkpointed. Their presence
does NOT establish a recoverable DB. Validate a separate scratch restoration
later, never point a producer at this copy or replay missing decisions.

Encrypt the verified preservation into a NEW7z archive, AES-256+header encryption,
using 7-Zip's hidden prompt, not argv/env/clipboard secrets. Test it, record its
full ciphertext size/hash privately, copy to the reconnected external disk using
destination-bound identity verification, hash/read/test there, then safely eject.
Optional same-account Drive: private upload/download hash equality and extraction
test in a NEW scratch location. It is an additional copy, NOT an independent
account failure domain. Exact extraction file names/sizes/hashes must reproduce
this manifest; do not open the copied journals. No scratch cleanup is implied by
these instructions. Off-PC copy/disk readback is still unproven until actually run.

The extension also supplies a READ-ONLY native ciphertext destination check,
so a stale PSDrive view cannot earn a copy-match claim. After physically
identifying/reconnecting the external disk and creating its NEW ciphertext
copy, probe that actual destination handle once; record its volume digest
privately. Enrollment is owner confirmation, never inferred from a drive letter
or Windows Fixed/Removable label. The check reads no file contents:

```powershell
& $backupRuntimePython -I -S -B .\standalone_backup_launch.py --operation preserve --reviewed-source $preservationReviewedSha --confirm-run --mode probe-cipher --cipher-destination $externalCipher
```

Then compare both actual ciphertexts against the previously recorded source
size/hash AND that independently recorded expected destination-volume digest:

```powershell
& $backupRuntimePython -I -S -B .\standalone_backup_launch.py --operation preserve --reviewed-source $preservationReviewedSha --confirm-run --mode verify-cipher --cipher-source $localCipher --cipher-destination $externalCipher --expected-cipher-bytes $cipherBytes --expected-cipher-sha256 $cipherAnchor --expected-destination-volume-sha256 $externalVolumeAnchor
```

Both files are read-held while their byte hashes and same-handle identities are
measured. Same-volume source/destination, wrong volume, bytes, hash or identity
block; nothing is copied or written by these modes. The5GiB ciphertext limit is
a planning/admission cap, not a reason to change pins or truncate a large file.
This is destination/byte proof, NOT proof of encryption, physical independence,
authenticated custody or restore. After7-Zip extraction into a NEW PRIVATE scratch
root, use the earlier --mode verify against the original manifest anchor to
check every extracted default-stream file, empty directory and both roots.
Do not use the old seven-original preservation inventory for this new cipher:
its fixed old ciphertext/selection anchors remain unchanged and separate.

Capture and DB backups are SEPARATE generations/contracts. Do not overwrite the
earlier seven-original inventory, A signing head, archive pins or encrypted
recovery artifact. A later authenticated witness can bind their immutable
digests and observation windows together; it must not claim one cross-system
atomic snapshot. The signing key is not the encryption passphrase.

## Database runway: measure first, explicit zero-cost decision and trigger

~345MB alone cannot determine days/weeks. The existing guard uses SUM of ALL
pg_database_size values, not just the current DB or cached dashboard. If345MB is
that SAME complete cluster metric, nominal headroom is155MB and margin above
the existing24MB admission floor is131MB. Otherwise those are only arithmetic
scenarios, not measured headroom. Local capture75 polls do NOT mean75 DB scans.

Use sql/backup_capacity_sample_read_only.sql, no business rows. The owner supplies
one stable NONSECRET source label for that project/session; it is not identity
authentication. In the same SQL session set only the transaction-local custom
label after BEGIN (before its WITH query), e.g. SET LOCAL
backup_capacity.source_id='primary-project-v1'; save the returned JSON privately.
Do not paste raw connection details or change privileges if measurement fails.
The recipe rolls back and has10s statement/2s lock timeouts. Size functions are
live observations even in repeatable-read, not an atomic physical-size snapshot.

Measure before and after each ACTUAL scheduled DB writer, after settling, and at
the same daily times over at least three complete samples spanning24hours. Note
which scan/research/maintenance jobs ran; do not trigger synthetic live writes
just to measure growth. The sampler includes cluster/current bytes, DB identity
inventory and exactly eight relation sizes/filenodes; missing/partition-parent
attribution stays explicit rather than silently claiming zero growth. Track local
capture bytes/free disk separately. Do not add WAL to the database quota metric.

backup_capacity_assessment.assess is pure: one point reports capacity but NO
forecast. It rejects mixed/stale/future/partial samples, requires matching source
inventories and uses the maximum positive observed interval rate only as a
diagnostic. Flat/shrinking data NEVER means infinite runway. All-writer admission,
notification delivery and authentication remain false/not established.

Decision: stay on Free/zero cost and commission hot/cold protections, not a paid
upgrade or another unmanaged free DB. Proposed operating triggers, INACTIVE:

- At<=64MB measured cluster headroom, or observed diagnostic runway<=20calendar
  days: urgent owner review, freeze adding new DB writers/data sources, prioritize
  authenticated restore/cold-reader/retention commissioning. A noisy short
  interval is not a calibrated forecast; escalate uncertainty, do not erase it.
- At<24MB: existing collector admission blocks. Hold affected writers if safe
  bounded retention is not commissioned; missing evidence remains missing.
- Unknown/stale/partial measurements: report UNKNOWN and do not assume runway.
- No deletion, compaction or grant change is authorized by a capacity report.

Historical0.75MB per scan is not today's measured rate. At exactly two scans/day
and no other growth,131MB would be roughly87trading days, but this is ONLY a
sensitivity scenario, not a promise or a new scheduling decision. Ledger/other
writers can dominate growth. Source allocation, encrypted dump size, WAL/system
disk, Drive quota and PC/external free bytes are different budgets.

## Native database backup order (existing accepted release can proceed now)

The owner's proposed order is correct, with source/check/audit gates around it:
clean exact merged backup checkout -> fresh dedicated3.13.9 runtime outside it
(ONLY four hash-locked packages) and separate audited36-package tool environment
-> full runtime AND tool audits/pip check -> manual Linux synthetic workflow
with its one temporary variable/confirmation -> remove variable -> Windows
directory drill -> pinned17.11 tools and verify-full CA local check -> fresh
capacity/disk/backup facts -> ONE supervised opaque live export, invoked ALONE.

Use NATIVE_EXPORT_RUNBOOK.md for its already-reviewed command shapes, but owner
delivery is ONE executable block at a time. No new code fix is needed first to
perform that existing release's synthetic native acceptance. Do NOT point its
old gate at the newly extended candidate tree or mix old/new reviewed SHAs.
Never upgrade the installed capture environment or rely on bare py/default3.15.
Native prompts happen only in a normal, unredirected console; no password URI,
passfile, transcript or credential environment variable. Local17.11 clients are
used without starting the non-loopback local server. Source permission errors
block; do not silently exclude schemas or accept incomplete logical exports.

Preserve all five files from any successful DB export. The4GiB native dump cap
and12GiB floor are unchanged, but require32GiB fresh working space for encryption/
copy/extraction planning, plus separately measured isolated-restore space.
Encrypted size is not derivable from345MB; use measured size, with5GiB per
generation as a planning allowance, NOT a bound or promise. Three encrypted
locations: working PC, offline external disk, private cloud readback. Keep ALL
current generations until an authenticated restore succeeds and a reviewed
retention policy is commissioned. Later target two recent +last restored baseline
(up to three distinct generations), without deleting the last proven baseline.

## After export: restore has to account for target event triggers

Encrypt -> destination-verified off-PC copies -> authenticated generation/custody
binding -> isolated typed restore -> intended-role and cold-reader proofs ->
bounded retention LAST. No step is inferred from the preceding one's hash match.
Database MVCC dump and global roles dump are not the same snapshot. Original
archive batches can overlap; explicit cross-batch version/conflict policy and
same-generation binding remain required. Structural eight-batch checks did not
change the original868/876 verifier acceptance or authorize deletion.

Inventory ALL source and empty-target event triggers BEFORE any schema DDL,
including ensure_rls/function body hash, enabled mode, tags, owners, extensions,
execution role and context. Existing target ddl_command_end triggers may enable
RLS during CREATE TABLE. A pinned search_path is not proof against that effect;
--disable-triggers is not a general event-trigger isolation switch. Use a
non-serving disposable target without host ports/outbound integrations, not the
existing non-loopback local server. Unknown triggers/platform dependencies block;
no blanket disabling, replica mode, privilege or ACL change is authorized.
Compare final RLS/force-RLS/policies/ACLs and test actual application roles, not
only postgres/owner. Main's v2 event-trigger review annex remains local pending a
separately accepted application package; do not import it across repositories.

## Long-run traps and carry-over decisions: no silent clearing

- Full copies of BOTH mutable trees every day would repeatedly duplicate history.
  This tool is an initial forensic cut, not commissioned long-run incremental
  storage. Next design immutable per-day capsules plus signed file manifests/
  content-addressed chunks and tested reconstruction; no mutable journal pruning
  until restore/retention acceptance. Snapshot growth and backup generations must
  each have budgets and alerts. At a bound/full disk STOP; never silently omit
  old files, wrap a manifest, overwrite a generation or reset a marker.
- Provider-free does not mean backup/sync/egress-free forever. Record current
  Drive entitlement, expiry/renewal terms, quota and owner access recovery; the
  reported5TB entitlement must not be assumed a permanent zero-cost free tier.
  Avoid paid API/runner/storage subscriptions and public data artifacts. An
  offline external disk is the independent physical lane; same-account cloud
  compromise, deletion and sync propagation remain correlated risks.
- Licences may restrict storing/processing market data even privately. Confirm
  permitted personal retention/cloud backup/research before commissioning ML or
  sharing anything. Source-only public tools are not permission to publish data.
- Encryption can hide corruption and lost keys can invalidate every copy. Keep
  passphrase recovery separate from all copies, test extraction, authenticate
  manifests separately, and rehearse restoration of the signing-key backup.
- Seven Linux-target PackageA typing errors remain OPEN in frozen helpers;
  repair in its owning repo and explicitly vendor-sync/reaccept, no ignore.
- Unclassified full Windows suite remains OPEN. The old helper's os.link and
  junction fixture failures were isolated to sandbox/temp context; normal-session
  synthetic40/3/28 passed. This does NOT clear the unrun full suite or prove a
  private copy. New full-root native tests have separate evidence in VERIFICATION.
- Rebuild ONLY fresh backup environments after capture. Preserve installed
  capsules/frozen dependencies; no bulk patching before Thursday.
- Production failure-alert routing remains UNPROVEN. Synthetic notification and
  source files are not delivery proof; defer full isolated failure-route drill,
  never deliberately break a real poll. No advisory watcher is running now.
- Windows Time12:48 stop/root dispersion remain UNATTRIBUTED; retain logs and
  independent fresh clock gates, no resync/service change by backup tooling.
- Missing14Oct saved audit remains NOT FOUND, not proof of missing observations.
  Legacy audit exit2/shared-root writes remain unresolved; do not recreate/reset.
- Receipt authentication, same-generation custody, typed restore, writer/cold-
  reader integration and retention remain explicit OPEN gates.
- Holiday-aware collector skip, OPTION_CAPTURE_ENABLED off and sessions JSON
  ending1Oct remain OPEN. Audit the reviewed official calendar/holiday behavior
  separately, no holiday retry, invented sessions or enabling option capture.
- ML/LLM/backtesting remain mandatory but GATED on licences, real labels and a
  preregistered frozen paper study. No training, rule retuning or trading action.
- Duplicate Downloads/.7z copies remain PRESERVED until authenticated inventory/
  restore and explicit cleanup authorization. No deletion in this package.
- quant_app.mf_nav authenticated SELECT/RLS-off is UNCHANGED/UNDECIDED. API
  exposure depends on schema/memberships/RPCs as well as the grant. Preserve
  facts and review consumers; no revoke, RLS enabling or privilege change without
  explicit owner authorization, even if a scanner calls it a finding.
- PR56/57 stay OPEN pending accepted replacements and explicit owner disposition.
  A separate green backup does not solve the app's Streamlit/Pillow advisory
  conflict. Dependency/security work must remain tracked, audit mandatory.
- Optional PR52: recommend owner close as superseded by merged PR53 AFTER
  retaining the review/CodeQL rationale; this does not delete private evidence or
  rotate a key. No GitHub write was performed and it remains open unless the
  owner actually closes it.
- New repository rules/security settings are DONE per owner, not a remaining
  blocker. No approval-count change or extra collaborator/account is required.

## Technology radar and next leverage

Adopted: existing native same-handle identities/denied write sharing, exact-base
scope migration, deterministic DACL queries without permission changes, whole-
profile hash locks/audits and pure capacity diagnostics. Adapted: opaque SQLite
sidecar preservation with integrity explicitly false, not live DB backup.
Considered but deferred: VSS (privilege/provider dependence), SQLite backup API/
sqlite3_rsync (would access a live DB or alter the recovery boundary), restic/Borg
(repository/key/restore commissioning overhead), terminal-control plugins and
agents with mutation authority. No paid feature or new installation is required
for this package. Runtime agents may report only; deterministic gates decide.

Highest leverage: protect the unique Wednesday cut and obtain ONE accepted live
DB export; then authenticate and restore that generation before retention or ML.

Sources consulted (21October, primary):
[SQLite copying hazards](https://www.sqlite.org/howtocorrupt.html),
[Supabase database/disk metrics](https://supabase.com/docs/guides/platform/database-size),
[Supabase backup guidance](https://supabase.com/docs/guides/platform/backups),
[event triggers](https://supabase.com/docs/guides/database/postgres/event-triggers),
[PG17 event-trigger catalog](https://www.postgresql.org/docs/17/catalog-pg-event-trigger.html).
