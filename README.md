# Decision: protect the database without waiving the application audit

## Current owner checkpoint: repository/settings DONE; preservation extension

The public sibling repository now exists. Owner reports green c311e08 checks,
225 Linux passes on both patches, synthetic resilience and CodeQL, merged as
70629fcc2a98814d6e0d8ea760ba27b70e5c819b. The protect-main ruleset and the
reported free security settings are DONE, not an outstanding owner step. No
agent changed those settings. The public exact-base manifest has been read and
the exact public source cloned; settings/CI remain labelled owner-reported.

For the NEW 38-file distribution and one exact-base13-path maintenance PR, read
CAPTURE_PRESERVATION.md FIRST. Do not repeat the older inert-seed/new-repository
instructions below. Existing native database backup acceptance can proceed on
the accepted30-file release independently; it does not need this extension.
The extension preserves BOTH quiescent Forward and ForwardOps roots as opaque
default-stream files, adds pure capacity sampling/assessment, and changes no
runtime locks, native exporter, signing helpers, artifact contract or workflows.
No private copy, export, custody, retention or task change is commissioned here.

Wednesday75/75 and both scheduled results0 are owner reports; saved audit15:40:26
is not authenticated journal or remote-custody proof. Preserve the unique local
cut before Thursday Prepare/Start. The new runbook contains the first read-only
readiness block; subsequent private commands are delivered one block at a time.

## Recommendation and authority

The previous recommendation coupled two different release units too tightly.
Waiting for an unknown Streamlit release is not a satisfactory protection plan
for a database with no established project backup. Build and review a separate
minimal backup distribution NOW. Keep the application's existing full audit
mandatory and failing while its affected dependency remains. No advisory
exception, changed branch protection, app deployment or claim of app security.

Recommended delivery: an owner-created, source-only PUBLIC sibling repository,
using existing free GitHub Actions and CodeQL. Private-repository CodeQL may
require payment; do not enable a paid feature. No private artifacts, account
tokens, CA files, dumps, signing keys or audit reports go into this repository.
The project endpoint/account strings already in public source are not passwords.
If the owner does not approve a sibling repository, the original PR merge is
still blocked; this package does not quietly redefine its required checks.

The new source profile is explicit: standalone-backup-v1. Default application-v1
retains its old admission. Neither mode falls back to the other. Only the owner
can approve an exact final source SHA and commission a native export after all
independent acceptance steps. Synthetic passes do not authorise hosted access.

## Options considered: risk, effort and decision

1. Wait for official upstream compatibility/backport. Lowest application change,
   unknown delay; leaves the database without new protection. Keep this route
   for the APP, not as the backup's only route. A bounded public watcher helps.
2. Separate audited backup distribution. Moderate one-off packaging/acceptance
   and one more source repository; minimal four-package runtime, existing opaque
   native export and independent tests. Recommended. Audit that WHOLE runtime
   and its whole test-tool environment; do not call it a full-app audit pass.
   Source duplication is controlled by frozen mappings/hashes, not manual edits.
3. Scoped monorepo CI that allows a backup-only PR despite app findings. Requires
   an owner-approved change to the repository's admission policy and convincing
   closed import/write/deployment scopes. Not chosen here: the current owner
   gate deliberately requires the full application audit on every PR.
4. Time-boxed exception for the eight exact advisory IDs. The static chart-path
   assessment reduces the demonstrated exposure, but it is not formal reachability
   proof. An exception changes risk acceptance, requires owner approval, expiry,
   review owner, narrow versions/uses and a non-suppressible expiration gate.
   NOT implemented or recommended to unblock a tool that needs no Pillow.
5. Replace only the chart renderer. Does not remove Streamlit's declared Pillow
   dependency; likely more regression work without resolving the graph. Reject
   as a fix for this audit. Replacing the complete framework is a separate,
   high-effort application migration, not urgent backup protection.
6. Force Pillow 13, edit metadata, drop the pin, use an unreviewed fork/nightly
   or skip the audit. Unsupported/hidden risk. Rejected; no such change made.

## Actual exposure assessment, not an exception or exploit proof

Official upstream advisories identify Pillow 12.3.0 as affected and 13.0.0 as
fixed. The reviewed normal path is reliable_charts -> Matplotlib Agg -> Pillow
RGBA frombuffer -> fresh PNG save -> Streamlit generic Image.open/resize/PNG
save. There is no direct app PIL import or observed active image-upload path.
Static inspection is not a complete proof about every input substitution,
optional library path, native build, current cloud environment or future code.

- [CVE-2026-112895 / PDF](https://github.com/python-pillow/Pillow/security/advisories/GHSA-p4wg-p73j-c528):
  recursive page-tree/trailer parsing, typically appending to an existing PDF.
  No PDF parsing/append observed in the generated-PNG path.
- [CVE-2026-112400 / GIF](https://github.com/python-pillow/Pillow/security/advisories/GHSA-65qm-jvmh-6pqg):
  seek a crafted later frame, catch the decompression-bomb rejection, then reuse
  the rejected object's dimensions in an allocating operation. No animated GIF
  seeking or rejected-object reuse observed.
- [CVE-2026-112397 / morphology](https://github.com/python-pillow/Pillow/security/advisories/GHSA-58r4-6rv3-gfh8):
  zero-width images in MorphOp.apply and related native row operations. No
  ImageMorph use; chart images have positive fixed dimensions.
- [CVE-2026-112896 / TIFF encoding](https://github.com/python-pillow/Pillow/security/advisories/GHSA-pchr-8j38-3x4p):
  retained incompatible ColorMap/sample-depth metadata while saving TIFF through
  libtiff. Fresh RGBA-to-PNG does not retain/re-encode TIFF metadata. Upstream
  demonstrates an over-read, not a general proof of arbitrary heap disclosure.
- [CVE-2026-112897 / TIFF decoding](https://github.com/python-pillow/Pillow/security/advisories/GHSA-q45j-58j2-45rg):
  short compressed strips/tiles can expose uninitialized pixels. Requires
  crafted libtiff decoding, and disclosure requires exposing resulting pixels.
  No TIFF strip/tile decoding observed on the chart path.
- [CVE-2026-112395 / tiled TIFF](https://github.com/python-pillow/Pillow/security/advisories/GHSA-462x-pgg6-55fp):
  tile-buffer over-read through copy4. No tiled-TIFF decode observed.
- [CVE-2026-112404 / TIFF layout](https://github.com/python-pillow/Pillow/security/advisories/GHSA-c6hw-5grf-ff96):
  malformed layout disagreements between Pillow and libtiff. RGBA mode alone
  does not invoke this TIFF decoder. No matching TIFF input observed.
- [CVE-2026-112899 / EPS](https://github.com/python-pillow/Pillow/security/advisories/GHSA-vx6w-vv9f-6gvg):
  scaled EPS/PS with available Ghostscript checks dimensions too late. No EPS,
  scaled EPS loading or Ghostscript operation observed.

Assessment: no matching prerequisites demonstrated in that inspected path;
NOT "unexploitable", not proof that every installed runtime is unaffected, and
not permission to process arbitrary image formats or waive vulnerability audit.
No exploit payload was run. Existing app/capture environments were not inspected
or patched. Prior isolated Pillow-13 behavior passes do not override <13.

## Separation design and what each gate proves

- SOURCE origin review base is exactly 563665a32e5454633b0c27256072a7249503c520.
  New unmerged backup bytes are explicitly hashed, not claimed to be on main.
  BACKUP_STANDALONE_UPLOAD.json lists every SOURCE -> DESTINATION and LF hash.
  Export copies only that fixed public set into a NEW destination, retaining
  partial output on failure. No environment, private folder or broad tree copy.
- The generated BACKUP_TOOL_DISTRIBUTION.json binds the exact complete target
  tree. Pre-commit check supports an unborn empty tree or an EXACT inert README
  seed base; the owner supplies that seed SHA explicitly. It does not accept
  arbitrary newer main. Runtime requires a different externally approved final
  commit SHA, clean tree, regular stage-zero files and all indexed/blob hashes.
  Ignored/untracked files are rejected too. Git replacement objects/grafts and
  ambient global/system Git configuration are disabled for those queries.
- standalone_backup_launch.py is invoked with -I -S -B using the explicit NEW
  runtime's Python 3.13.9. It checks the source before any product/site import,
  admits exactly four distribution versions, then adds only the reviewed source
  and that dedicated environment's site-packages. No .pth/sitecustomize/user
  customization execution, no ambient PYTHONPATH. This is not OS sandboxing,
  native binary attestation or protection from a compromised OS/interpreter.
  The trusted entrypoint checks its own and the gate's bytes against the external
  commit using stdlib/Git BEFORE executing committed gate source directly; it
  does not import an unchecked gate or cached bytecode. Interpreter, Git and
  that reviewed bootstrap remain the explicit trust base, not self-attestation
  against an already malicious entrypoint or concurrent hostile same-user code.
- Runtime lock: cryptography 50.0.1, cffi 2.1.1, pycparser 3.0, packaging 26.3.
  The public watcher uses packaging; opaque backup does not need Streamlit,
  Pillow, certifi, pandas or a database Python driver. The existing native
  PostgreSQL tools perform verify-full TLS against the owner-pinned CA.
  Python audits do NOT audit PostgreSQL/OpenSSL DLLs, Windows, Docker or the CA.
- Test/audit lock is a separate fully pinned/hash-checked dependency closure.
  CI audits BOTH complete runtime requirements and the complete installed test
  environment, runs all bundled synthetic tests and CodeQL/scanning. No
  --ignore-vuln, continue-on-error, missing-finding success or forced resolution.
  Hashes cover reviewed CPython-3.13 wheels on Win AMD64 / Linux x86_64, not
  arbitrary OSes. See [pip secure installs](https://pip.pypa.io/en/stable/topics/secure-installs/).
  Before each newly commissioned live export, rerun the complete runtime audit
  and review its point-in-time result; yesterday's green CI is not a permanent
  security attestation. Lookup failures block admission, not an automatic waiver.
- Manual Linux Docker conformance remains default-off with its confirmation and
  variable. Windows directory-lock acceptance must pass on the new exact source
  after capture/audit. Neither was commissioned by the builder. Separate source
  distribution is not data custody, a source backup, typed restore or deletion
  admission. Roles dump and DB dump are not claimed to share one snapshot.

## Python patch difference and supported-pair notification

The old review modeled 3.13.9 only; hosted CI used 3.13.16. The unconditional
Streamlit Pillow<13 bound rejects 13 on both. A full-version marker CAN differ,
so the reviewer now supports explicit 3.13.9 AND 3.13.16, and tests demonstrate
that distinction. The watcher requires metadata compatibility for Windows and
Linux on both patches; neither is inferred from the running host. No change to
capture's required 3.13.9, source pins or clock gate.

dependency_pair_watch.py previews with zero IO. Explicit public-network mode
makes at most five bounded HTTPS GETs to PyPI: pinned/latest stable Streamlit,
latest Pillow, a newer 12.x backport if listed, and reviewed 13.0.0 if needed.
Candidates must have an explicitly empty vulnerability list and metadata support
on all four targets. Missing data/network failure is UNKNOWN, not green. A
candidate still needs whole-graph install/audit/behavior/full-suite review.

dependency_pair_watch.ps1 is an OWNER-LAUNCHED bounded foreground watcher, NOT an
installed task or hosted workflow. Default Preview has zero requests/settings/
task changes. After standalone merge, owner can launch Watch for eight checks
two hours apart, through the isolated launcher in the new runtime. It pops up
only for a newly observed compatible candidate in that invocation; unchanged
checks remain popup-quiet. It stops visibly on unverifiable metadata. No webhook,
email secret, plugin account, install, automatic pin edit or capture dependency.
It works only while this separate process/PC is awake and running. Nothing is
currently watching. Longer-term persistent scheduling needs explicit owner
commissioning; no background promise is made from merely writing the script.

## Owner sequence: one block at a time, normal PowerShell

### Corrected export and privacy boundary (21 October refresh)

The first 26-file export is superseded, NOT accepted for publication. Keep it
unchanged outside any upload clone; do not overwrite, delete, stage or upload it.
Use a DIFFERENT not-yet-existing directory for the corrected **30-file** export.
The exporter and staged checker now reject literal Windows/macOS/Linux home
profile paths across every payload, including docs, tests, workflows and JSON.
This is a privacy regression guard, NOT a secret scanner or complete anonymity
proof. Review the exact exported tree before committing; no private files belong
in this repository. Fixed public project endpoint/account and the reviewed
Program Files PostgreSQL installation path remain intentional functional values.
No personal user directory is needed. Synthetic test identities are not accounts.

The exact source origin base, inert seed content, externally supplied seed SHA
and externally approved final SHA remain unchanged gates. The new file list is
the source manifest's exact `destinations` mapping; the generated target manifest
adds itself as the thirtieth file. Do not combine this package with the retired
37-file application upload. The source manifest is NOT a target file.

For the preview below, $reviewedWorkspace is the owner's absolute source-tools
directory, not a capture capsule. Choose it locally; no personal path is printed
in this public runbook. The owner receives and executes only ONE block at a time.
Do not run later examples merely because they appear in this complete runbook.

Do not run any of these against the installed capture. Finish today's final
poll and 15:40 audit before runtime/native acceptance. Public source review and
CI preparation do not modify or depend on that capture.

1. The owner has approved the route in principle; review this corrected public
   package before creating the seed repository. Existing
   application audit/branch protection/PRs #56/#57 stay unchanged and unmerged.
   The recommended route does not require a paid account or any DB secret in CI.
2. Review the source manifest and this decision. From the source workspace,
   run the export preview with the existing explicit 3.13.9 test interpreter:

```powershell
$ErrorActionPreference='Stop'
$python3139=Join-Path $reviewedWorkspace '.venv\Scripts\python.exe'
& $python3139 -B standalone_backup_contract.py
if($LASTEXITCODE -ne 0){throw 'Preview rejected'}
```

3. Select a NEW public-tools output directory outside any capture/private root.
   Do not pre-create it. Set $backupPublicOutput to that absolute path, then:

```powershell
$ErrorActionPreference='Stop'
& $python3139 -B standalone_backup_contract.py --export-to $backupPublicOutput --confirm-public-export
if($LASTEXITCODE -ne 0){throw 'Preserve partial output; review, do not retry'}
```

4. Owner creates a public sibling repository with ONLY this inert README on its
   initial main (LF bytes, trailing newline). This is a visible bootstrap, not
   an executable package and not a bypass of the application's branch rules:

```text
# Standalone backup review seed

No executable tooling; no backup authority.
```

   Record the exact seed commit as $backupSeedSha. Clone it clean with
   core.autocrlf=false, verify that exact SHA and the one-file seed, create a PR
   branch, copy the exact exported target list, and stage only those paths.
   The checker refuses any other seed tree/content. This TARGET seed SHA cannot
   be invented before the owner creates it; SOURCE base is pinned above.

   For the copy/stage block, set $backupUploadClone to the NEW clean clone,
   $backupPublicOutput to the completed exporter output, and $backupSeedSha to
   the externally recorded seed SHA. Do not use an existing application clone:

```powershell
$ErrorActionPreference='Stop'
$actualSeed = git -C $backupUploadClone rev-parse HEAD
if($LASTEXITCODE -ne 0 -or ([string]$actualSeed).Trim() -cne $backupSeedSha){throw 'Wrong seed SHA'}
$targetManifest=Get-Content -LiteralPath (Join-Path $backupPublicOutput 'BACKUP_TOOL_DISTRIBUTION.json') -Raw | ConvertFrom-Json
foreach($name in $targetManifest.files.PSObject.Properties.Name){
    if($name -notmatch '^[A-Za-z0-9_./-]+$' -or $name.StartsWith('/') -or '..' -in $name.Split('/')){throw 'Unsafe public relative path'}
    $target=Join-Path $backupUploadClone $name
    New-Item -ItemType Directory -Path (Split-Path -Parent $target) -Force | Out-Null
    Copy-Item -LiteralPath (Join-Path $backupPublicOutput $name) -Destination $target -Force
    git -C $backupUploadClone add -- $name
    if($LASTEXITCODE -ne 0){throw 'Staging failed'}
}
Set-Location -LiteralPath $backupUploadClone
```

```powershell
$ErrorActionPreference='Stop'
& $python3139 -B standalone_backup_contract.py --check-staged --base $backupSeedSha
if($LASTEXITCODE -ne 0){throw 'Exact target base/source review failed'}
git diff --cached --check
if($LASTEXITCODE -ne 0){throw 'Whitespace failed'}
```

5. Test with the complete hash-locked test environment OUTSIDE the clone; use
   its explicit interpreter, -B, pytest -p no:cacheprovider, and a new temp
   directory. Run pip check, all bundled pytest, both audits and pyflakes.
   Check repo-local Git identity presence before committing. Owner commits and
   opens PR; no attribution/trailers, plain one-line PR description. Require
   exact-final-SHA Backup quality (both patches), CodeQL AND Code scanning
   results. Owner alone merges. No hosted CI pass exists for this new package.

   Focused/full-bundled test line ($backupTestPython is the explicit NEW test
   environment interpreter, NOT the four-package runtime; it must be 3.13.9):

```powershell
$ErrorActionPreference='Stop'
$backupTests=Join-Path $env:TEMP ('backup-tests-'+[guid]::NewGuid().ToString('N'))
& $backupTestPython -B -m pytest -q -rs -p no:cacheprovider --basetemp $backupTests
if($LASTEXITCODE -ne 0){throw 'Bundled backup tests failed'}
$backupPythonFiles=@(Get-ChildItem -LiteralPath . -File -Filter '*.py' | ForEach-Object {$_.Name})
& $backupTestPython -B -m pyflakes @backupPythonFiles tests
if($LASTEXITCODE -ne 0){throw 'Backup lint failed'}
& $backupTestPython -B -m pip check
if($LASTEXITCODE -ne 0){throw 'Backup dependency graph failed'}
& $backupTestPython -B -m pip_audit -r requirements-runtime.txt
if($LASTEXITCODE -ne 0){throw 'Complete backup runtime audit failed'}
& $backupTestPython -B -m pip_audit
if($LASTEXITCODE -ne 0){throw 'Complete test/tool environment audit failed'}
```

   New test environment install is the same bootstrap pattern as runtime, but
   uses requirements-test.txt (it includes pip/pytest/auditor). Keep it outside
   the checkout. Check local Git identity presence, with no value printed:

```powershell
$ErrorActionPreference='Stop'
$null=git config --local --get user.name
if($LASTEXITCODE -ne 0){throw 'Set your repo-local Git name yourself, then review'}
$null=git config --local --get user.email
if($LASTEXITCODE -ne 0){throw 'Set your repo-local Git email yourself, then review'}
```

   A present identity does not authorise a commit. Owner creates one reviewed
   commit and PR using the normal routine; include the separate Backup synthetic
   resilience check in the exact-final-SHA green requirements. This is not the
   application's resilience game day. Do not upload the seed/bootstrap process
   as an application audit workaround.
6. Create a NEW runtime venv --without-pip OUTSIDE the clean merged tools clone.
   Use the bootstrap interpreter's pip --python <new-env-python> install with
   --require-hashes --only-binary=:all: -r requirements-runtime.txt, then pip
   check. Never upgrade today's installed capsule or rely on bare py.
7. Run manual Linux synthetic workflow after explicitly commissioning its
   variable/checkbox; remove enabling variable afterward. Then the separate
   Windows directory drill via the isolated launcher; preserve any partial or
   unknown outcome. No service/ACL/listener changes or real DB operation here.
8. Only after those gates, approve one real opaque native export using the
   original backup runbook's pinned tools/CA/confirmations, PLUS explicit
   standalone profile and exact final source through the launcher:

```powershell
# SHAPE ONLY: do not run until native acceptance and explicit export approval.
# $backupRuntimePython is the NEW dedicated 3.13.9 environment's full path.
# $backupReviewedSha is the externally reviewed final sibling commit, not HEAD discovery.
& $backupRuntimePython -I -S -B .\standalone_backup_launch.py --reviewed-source $backupReviewedSha --operation backup --confirm-run --mode directory-drill --run-root $newSyntheticDrillRoot --confirm-no-capture-running
```

   Real export still requires --mode export, fresh private output, all tool
   hashes, CA and original attestations. The original source backup instructions
   remain a prerequisite; do not infer permission or fill secret arguments from
   this shape. No retry of a consumed attempt, no restore/deletion claim.
9. Optional, after merge/runtime admission: in a separate normal PowerShell,
   start the public watcher (no hosted setting changes):

```powershell
$ErrorActionPreference='Stop'
.\dependency_pair_watch.ps1 -Mode Watch -Python $backupRuntimePython -ReviewedSource $backupReviewedSha -ConfirmPublicNetwork
if($LASTEXITCODE -ne 0){throw 'Watcher stopped; review public observation'}
```

## Ownership, data interface and upkeep

The main application repository owns capture, preservation-signature semantics,
archive verification, custody, conflict policy, restoration and all deletion
gates. The sibling owns its opaque native export, isolated source/runtime gate,
dependency locks and synthetic backup acceptance. The copied preservation and
legacy checker helpers are VENDORED snapshots: their reviewed hashes in both
manifests must not drift silently. A main helper repair (including Linux typing)
requires a deliberately reviewed sibling vendor-sync PR, changed hashes, bundled
tests, whole-profile audits, exact-SHA CI and renewed affected native acceptance.
No submodule, moving branch, shared venv, pip-installed application or import from
the other checkout is allowed. The sibling is not a second authoritative fork of
the preservation protocol. New source fixes have to be reviewed in their owning
repository and then explicitly carried across where used.

The initial --check-staged mode still accepts only the exact inert seed (or
unborn tree), NOT an ordinary release base. A SEPARATE --check-update --base
<externally-approved-prior-release-SHA> mode handles later maintenance: it
requires HEAD at that approved release, verifies its entire committed manifest,
scope, modes and payload hashes, THEN verifies the complete candidate staged
tree, index/worktree agreement, privacy and new manifest. It never accepts
arbitrary HEAD discovery, a seed as a release, missing old files or an incomplete
candidate. Distribution scope/format changes and changes to the published
artifact-interface bytes deliberately fail closed and need a separate reviewed
migration gate; ordinary maintenance cannot silently reinterpret that contract.
This does not mechanically prove arbitrary code changes preserve semantics.
Unit tests exercise this update path; a real
committed maintenance rehearsal is still NOT VERIFIED because no target repo
or approved release exists. Final-SHA CI/runtime gates remain mandatory too.

BACKUP_ARTIFACT_INTERFACE.json is the versioned DATA contract. The original
live-logical-backup-v1 manifest is unchanged. A pure synthetic-tested projection,
backup_artifact_contract.project, accepts supplied opaque measurements and
projects exact original-byte SHA-256/length records, the externally reviewed
producer SHA and explicit non-authority flags. It performs no file or DB IO,
does not authenticate supplied measurements and is NOT commissioned custody.
The restore consumer must implement its own strict reader, independently rehash
all files, reject unknown versions/extra names and authenticate the witness.
It must NEVER import this sibling module or execute roles.sql / TOC as a script.
Exact-byte data hashes do not use the LF normalization used for PUBLIC SOURCE.
Roles export and database export do not share one MVCC snapshot; same-generation
A/B binding, cross-batch versions and conflict admission remain main-repo work.
Changing this wire contract requires a versioned producer/consumer migration,
not a reinterpretation of old unsigned artifacts. Stable source SHA recorded
outside the checked tree, signatures and rollback policy remain separate duties.

Runtime FOUR and tooling THIRTY-SIX locks stay complete and mandatory-audited.
Hash locks prevent silent replacement, not newly discovered vulnerabilities.
Dependency updates are human-reviewed PRs: obtain official metadata/hashes,
resolve both Windows/Linux targets and Python patches, recreate clean venvs,
run all bundled tests, both audits, source check, lint and exact-SHA CI. Never
let Dependabot edit one hash/version and auto-merge an incomplete lock.

An optional advisory.yml template reuses the COMPLETE quality/audit workflow
daily at 02:17 UTC and on manual dispatch, only if the owner commissions
BACKUP_ADVISORY_WATCH_ENABLED=true. It stays skipped by default; no variable
has been set. It checks BOTH profiles, does not patch dependencies, use private
credentials, export data or touch capture. GitHub Actions failure notifications
must be enabled and tested by the owner; a workflow file alone proves no alert
delivery. Scheduled public workflows can be delayed or disabled after inactivity;
review their last successful timestamp and keep pre-export audits mandatory.
The local Pillow-pair watcher remains a separate opt-in foreground tool, not
proof that the app dependency issue has been resolved.

### New public repository: owner settings, no paid features

After creating the exact inert seed, require PRs and exact-head passing quality
on both Python patches, Backup synthetic resilience, CodeQL and Code scanning
results before executable tooling merges. Prevent force pushes/deletion and
apply rules to administrators. Preserve owner-only merges, conversation resolution
and no bypass. Require another HUMAN review only when a genuinely independent
authorized reviewer exists: an agent review is not a GitHub approving identity,
and a solo owner cannot approve their own PR. Do not pretend a setting exists
before it has been observed on the new repository.

Enable free dependency graph, Dependabot alerts, secret scanning and repository
push protection; subscribe to security/Actions failures and test notification
delivery. Confirm GitHub recognizes BOTH requirements files; its graph is an
additional signal, never a replacement for the two complete pip-audit checks.
Use the supplied advanced CodeQL workflow, not a duplicate default setup. Keep
Actions token read-only except CodeQL's narrowly scoped security-events upload.
Do not store DB/Drive/signing secrets or private artifacts in Actions, releases,
caches, issues or Git. Keep native/manual variables and advisory watch OFF until
separately commissioned; no auto-merge, auto-delete, deployment, production cron,
paid runner, paid security product or third-party terminal plugin is required.
Fork PRs are untrusted: do not add pull_request_target, secret access or writable
tokens to execute their code. Logs/test artifacts must stay synthetic only.

These features are available for public free repositories; verify actual UI
availability without buying an add-on:
[branch protection](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-protected-branches/about-protected-branches),
[security features](https://docs.github.com/en/code-security/getting-started/github-security-features).
Public code publication is durable; an accidental secret requires rotation,
not merely deleting the visible file. Two repos also mean TWO independent CI
and advisory histories; a green backup result never clears the app's Pillow gate.

## Capacity and generation policy BEFORE the first private export

Owner-reported, not remeasured here: database about 345 MB, Free limit 500 MB,
C: about 87.8 GB free; external disk offline. The difference is about 155 MB
nominal DB headroom, or 131 MB above the existing 24 MB collector floor, IF
the measurements cover the same cluster/quota metric. Do not infer a fresh
runway from an old per-scan estimate. DB allocation, a compressed pg_dump and
an encrypted archive have different sizes; none can be derived reliably from
345 MB. No encrypted-size claim is made before actual encryption/readback.
[Database versus disk size](https://supabase.com/docs/guides/platform/database-size)
also distinguishes WAL/system disk from database quota.

Keep the 4 GiB dump cap and 12 GiB native free-space floor unchanged. The three
artifact maxima total 4.03125 GiB, plus small manifests/attempt metadata. The
12 GiB floor admits the bounded native operation, NOT encryption, another
generation or a restore. For the first preservation sequence require a fresh
owner measurement of at least **32 GiB free on the working volume**, no concurrent
large export/restore, and available external/cloud space before proceeding.
This is an additional operating budget, not a weakened code gate or a guarantee
about future restoration. Plan up to **5 GiB per encrypted generation** as a
conservative allocation allowance, NOT a promised encrypted size or format bound;
measure ciphertext and stop/replan if it exceeds the allowance. Allow another
4.03125 GiB for one full extraction verification. A 32 GiB isolated-restore
reservation is only a starting budget to validate from actual dump, relation,
index, TOAST, WAL and extension requirements; it is NOT proven sufficient.
Do not run that restore on the owner's existing non-loopback PostgreSQL service.

Initial target: THREE encrypted copies of each admitted generation: working PC,
external disk verified by native destination identity then safely disconnected,
and private cloud upload/download hash-equal readback. The cloud shares the
owner's Google account and is NOT independent of account compromise/loss;
the offline physical disk supplies a different failure domain, not the cloud.
Keep passphrase custody separate and never use it as a signing key. Do not put
the only decryption secret in the same account or disk as all copies. Existing
archive preservation and new DB generation remain separately identified.

Keep ALL current generations until a successful authenticated restore and an
explicit retention policy. Once that later gate is commissioned, target two
recent admitted generations PLUS the last successful restore baseline (up to
three unique generations), retaining an older baseline until its successor is
restored. That is up to 15 GiB ciphertext allocation per location under the
planning allowance, not current measured usage. No automatic pruning, overwrite
or authorization to discard the current unsigned/failed evidence. If capacity
cannot preserve a new generation AND the baseline, stop new backup admission
and report; never silently discard the last good copy to make room.

After commissioning, aim for one preserved generation per capture day (one-day
recovery-point objective, not currently achieved or scheduled). A second export
is not needed merely to test encryption. Check free space and full runtime
audit before each approved export; keep measured growth and remaining capacity
in the private generation inventory. At DB headroom below 64 MB, review hot/cold
commissioning urgently; below the existing 24 MB admission floor, writes stay
blocked. These are proposed operating thresholds, not a new active monitor.
Zero cost is hard: do NOT upgrade or move to another free DB as an emergency
substitute for custody/restore. Commission dedup/guarded retention BEFORE growth
exhausts headroom; if they cannot be proven in time, hold affected writers rather
than exceed quota or delete unprotected data. Logical backup itself does not
reclaim source quota and no database deletion is authorized by this plan.

## Event-trigger-aware restore plan (main repository, inactive)

Owner-reported public tables/views absent, public rls_auto_enable() and database
event trigger ensure_rls present, ddl_command_end, owned by postgres with pinned
search_path. This is not a builder observation of the database or function body.
Pinned search_path controls name resolution, not whether the trigger changes
RLS. A pre-existing target trigger can run during CREATE TABLE and enable RLS;
the exact outcome depends on its body, enabled mode, restore role and platform.
Supabase's documented example affects newly created PUBLIC tables; do not infer
that this owner's function has identical code or covers other schemas.
[Supabase example](https://supabase.com/docs/guides/database/postgres/event-triggers),
[PostgreSQL event-trigger behavior](https://www.postgresql.org/docs/17/event-trigger-definition.html).

pg_dump's restored event triggers are post-data objects, but that does not
neutralize a trigger ALREADY present on a fresh target. pg_dump emits ENABLE
RLS for enabled source tables, not a compensating DISABLE for each disabled
source table. Therefore matching dump completion/row counts alone can conceal
target RLS drift. --disable-triggers is NOT general event-trigger containment.
Supabase role/platform behavior also differs from stock superuser PostgreSQL;
no outcome is assumed from the role name postgres alone.
[PG17 dump source](https://github.com/postgres/postgres/blob/REL_17_STABLE/src/bin/pg_dump/pg_dump.c),
[pg_restore options](https://www.postgresql.org/docs/17/app-pgrestore.html).

The local review-only access comparator/query now use restore-access-facts-v2:
ALL database event triggers, including functions outside application schemas,
enabled state, NULL-versus-empty tag filters, owner/function binding, security
attributes and in-database hashes of function definition and search_path.
No raw function body is returned. v1 inputs cannot silently omit this category.
This main-repo work is NOT included in or imported by the sibling backup package;
its four-path review annex is recorded in the local handoff, pending main's
security gate and a separately reviewed exact-base PR. No hosted query was run.

Restore order: source facts and extensions/platform inventory -> empty isolated
target facts BEFORE any DDL -> reviewed trigger execution/context policy ->
isolated restore -> final facts comparison -> intended-role positive/negative
access tests -> same-generation/cross-batch conflict proof. Unknown triggers,
platform dependencies or context block; never auto-disable triggers, alter
replication mode, grant privileges, open listeners or change ACLs. Prefer a
non-serving disposable target with no host ports/outbound integrations; a fresh
Supabase project is not necessarily empty PostgreSQL. Matching hashes are not
behavioral equivalence, API configuration, authenticated provenance or custody.
mf_nav grants stay unchanged pending explicit owner decision and consumer review.

## Today's capture and next operational order

Owner-reported 21 October: scheduled poll and audit result 0; saved report 75
recorded, 0 missing. This meets the stated post-session timing prerequisite
for NATIVE SYNTHETIC backup acceptance, not the unrun acceptance gates themselves.
It does NOT authenticate the journal, raw observations or remote custody.
No capture, journal, task, installed interpreter or private source was read or
changed here. The old capture capsule/environment must remain frozen.

Priority: corrected PUBLIC export/seed PR/exact-SHA green -> clean separate
runtime and both synthetic native gates -> fresh capacity and tools/CA facts ->
one approved opaque DB export -> encrypted verified copies and signed generation
binding -> isolated event-aware typed restore -> cold readers -> retention LAST.
Preserving today's unique capture is an independent high-priority lane, not a
reason to rerun a poll, re-audit a missing slot or alter its state.

For capture preservation, first establish no active writer and the exact dated
session root. The existing forward_evidence_preserve.py is a separate reviewed
owner tool, NOT part of this backup distribution. It makes selected opaque
copies with before/copy/after hashes, never opens SQLite, and blocks if producer
locks or SQLite WAL/SHM/journal sidecars exist. Its ACL checks only QUERY existing
permissions; a rejection is not permission to repair ACLs or remove sidecars.
Use only its separately reviewed exact-source route and a NEW private destination
with pre-existing suitable permissions; then encrypt/copy/test to the reconnected
external disk and private cloud, with destination-bound verification. Preserve
the generated manifest and original state unchanged. The helper is selected-
session preservation, NOT a complete operational image: ops reports, scheduler
definitions and saved audit need a separately scoped inventory/copy. Until exact
scope and quiescence are established, do not issue a generic recursive zip/copy,
SQLite checkpoint or --backup-only command from an older producer. These steps
are NOT run, and no off-PC capture copy is claimed. We will issue one owner block
at a time, starting with the public preview, not a private export or mutation.

## Every carried item: deliberate disposition, none silently cleared

- Seven Package A Linux-target typing errors: unchanged pinned helper; separate
  repair/reacceptance, not suppression. New source bootstrap/contract/watch code
  gets strict checks separately. Those errors are not erased by a profile split.
- Unclassified Windows full-suite failures / os.link WinError 5: remain open.
  No ACL change, fallback or new skip; no claimed complete Windows app pass.
- Installed environments: no reads/patches before today's audit; later inventory
  only with explicit interpreter, rebuild fresh profiles, preserve frozen code.
- Native backup acceptance: available next through isolated synthetic gates,
  not done by building a separate package. Source DB backup facts/capacity and
  all full-restore/cross-batch decisions remain unestablished until measured.
- Signed A/B/new-backup collector, authenticated custody/receipt authenticity,
  same-generation typed restore, cold readers, retention and Drive failure domain
  remain separate gates. Signed observations and opaque bytes are not custody.
- Production alert routing, time stop/root dispersion, missing 14 Oct saved
  audit, legacy exit 2/shared-root writes: defer to bounded operational review;
  do not disturb running capture, infer causes or reset markers.
- Holiday-aware skip, option capture off, sessions JSON ending 1 Oct: still
  open, no replay/backfill/calendar invention or enabling in this package.
- ML/backtesting/LLM: mandatory later deliverables, licences/labels/frozen paper
  evidence gates unchanged. No real training, retuning or performance claims.
- Duplicate Downloads/.7z files: preserve until authenticated inventory/custody
  and restore; no cleanup.
- mf_nav grant: dormant least-privilege finding, not silently revoked. First
  preserve source owner/membership/ACL/RLS/default-policy facts and confirm
  consumers; any narrow revoke needs explicit owner authorization. No blanket
  USAGE/grant/RLS change. Public tables absent does not prove public functions,
  views, security-definer RPCs or exposure settings absent. The new owner report
  narrows this to no public tables/views and one reported event-trigger function;
  actual API settings and function behavior remain unverified. Previous read-only
  catalog collector includes these classes and now global event triggers; API
  settings need separate owner observation. Do not confuse equal catalog digests
  with API equivalence.
  That collector is still local review-only work, not established as merged,
  commissioned or run against this database. No public-function/view absence
  or current API reachability conclusion has been made by the builder here.
- PR56/57: remain open/unmerged; close only after the owner has an accepted
  replacement for the intended deliverable. A sibling backup pass is NOT app
  remediation or justification to close unresolved application security work.

## Evidence and technology radar

Owner-reported: PR57 Linux 7244/277/76 and certifi clear; today's final poll/audit
result0 and saved75/0 report, unsigned and not remote custody. Builder-verified facts and final test counts are recorded in
BACKUP_DELIVERY_VERIFICATION_2026-10-21.md. All new hosted exact-SHA CI/native,
real backup/custody/restore/retention results are NOT VERIFIED until run.

Adopted: official PyPI/upstream advisories, pip resolver and hash-checked binary
locks, isolated environment profiles, separate free source/CI release unit,
deterministic source gate, -I -S -B bootstrap, existing disposable native recipe.
Adapted: PEP 508 markers to both real Python patches; local bounded popup watch.
Rejected: audit exceptions, source framework forks, forced resolution and
irrelevant paid/plugin dependencies. Separate builder/checker source reviews
remain required. No new agent makes trading decisions or changes a safety gate.
Highest leverage: one accepted opaque live source backup, then authenticated
custody and a same-generation isolated typed restore with conflict policy;
do not spend the next week only improving a hypothetical app dependency pair.
