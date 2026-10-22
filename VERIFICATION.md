# Verification ledger: standalone backup delivery review

## Windows directory guard defect and reviewed candidate (base4f65e7d)

Owner reported blocked drill, guarded-moved/attempt.json remaining, and no source
connection/tool checks/export attempted. Builder did not inspect that private
folder. A NEW synthetic fixture on Windows build26300 reproduced the metadata-only
rename gap and verified LIST_DIRECTORY-based sharing denial with no ACL changes.
Separate-process rename denial and post-release successful renames are tested.
Held-handle/expected/pathname identities must also agree using full64/128-bit
native IDs and a single pathname-stat observation; high-bit drift/query failure
tests reject disagreement. Source binding is not inferred from a pathname alone.
This proves synthetic API behavior, not the owner's private destination, host
integrity, authenticated custody or permission to export. Final test counts and
exact-source packaging checks are recorded in the PRIVATE upload/handoff guide.

The same implementation is inherited by two-root preservation destination/source
directory guards. Previous hash/readback/extraction evidence remains bytes-only.
The independent capture-only source has no import of these two backup modules;
no capture files, state, task, clock gate or source window were changed.
New hosted Windows guard job and owner drill on a NEW merged release are pending.

## 22 October native fixture repair

Builder reproduced the packaging-string mismatch using the unchanged public
image digest: actual version includes `(Debian 17.11-1.pgdg12+2)`. The repaired
fixture completed all ten native cases through the Windows Docker Desktop
Linux-engine adapter, with stopped-container verification true. This is local
Linux-container execution, NOT hosted acceptance, a Windows directory drill,
private restore, authenticated custody, or permission to export/delete.

The exact packaged version remains mandatory. Only fixed allow-listed failure
phases and exit integers 1..255 can be reported; raw errors are never logged.
The original hosted failure and previous acceptance records remain preserved.
Fresh hosted exact-SHA CI and a NEW manual native conformance run are pending.
Independent review identified Bash's inverted-command errexit exemption in the
old password-absence assertions. Those assertions now fail on a match OR a grep
error; real-shell negative tests are included. No exporter or workflow changed.

Final builder suite results: native Windows Python3.13.9, 362 passed/7 skipped,
27 subtests; Linux Python3.13.9, 366 passed/3 skipped, 27 subtests. Windows skips
include five POSIX-shell cases; Linux skips include two Windows-sharing cases.
Skips are not claimed as acceptance. Strict typing of the repaired module and
local packaging/checking helpers is clean; this does not clear legacy app typing.

## Follow-through maintenance on accepted475185c1 (22Oct)

Separate source-verified capture hold: public125153... profile AND constraints
declare certifi2026.7.22. Critical advisoryGHSA-6q48-6c7w-9gw2 covers it; no
private installed environment or compromise was inferred. Capture needs a new
reviewed profile; four-package backup runtime has no certifi and the separate
tool/test lock pins patched2026.10.19. Backup audit success
is not app/capture audit success or permission to install affected frozen pins.

OWNER-VERIFIED/REPORTED: PR2 merged475185c1b54d78ca5be66bbe9f71bbd5888be868;
head9145fad hosted328 passed/3 skipped on both Python patches, audits green.
1106-file10651004-byte two-root cut/manifest verification, encrypted external USB
destination check and extraction+all-file verification succeeded. Initial bad
ciphertext did not count; good replacement and originals remain unchanged.
Builder did NOT access any private copy, credential, journal or task.

New SAME-SCOPE maintenance: seven existing target files change, total38 remains.
Source-name rejection is before metadata/payload reads, batch-preflighted for
source AND export destination and candidate-index names. Names are case-folded,
nested/backslash/suffix forms included; exact scope/hashes/source gates remain.
Renamed-secret detection, history scanning or guaranteed manual-bypass prevention
are NOT claimed. Local workspace helper/ignore changes are NOT public payload.

Builder focused source-gate/local-guard/runbook suites:104 passed, no skips
(86 public source-gate tests,18 local helper/runbook tests). Full public
Windows/Linux results and final staging evidence are recorded in the private
follow-through handoff after final closure. Exact-final-SHA hosted CI remains
mandatory; historical green checks are not new candidate acceptance. Original
native backup acceptance, real export, same-generation typed restore/custody/
cold readers/retention remain open. No requirement/workflow/exporter changed.

## Historical verification records (superseded status where noted)

## Current two-root extension (previous release/settings owner-completed)

Owner reports the30-file release green on c311e08 and merged at70629fcc..., with
225 Linux tests on both patches and reported repository protections completed.
Those are owner reports, not newly builder-run hosted checks. Builder verified
the public exact-base manifest and cloned that source with no remote writes.

NEW source-only extension: complete distribution38 files, exactly13 changed
paths in its explicit predecessor-anchored scope migration. Existing native DB
exporter, conformance recipe/workflow, artifact interface, vendored preservation
helpers and4/36-package locks are unchanged. The initial seed, same-scope update
and exact-final-SHA gates are not relaxed. New product mode is preserve only.

Current builder evidence before final packaged-tree closure:

- Complete packaged Windows suite in the separate36-package tool environment:
  **329 passed, 2 skipped, 27 subtests passed**. Skips: unavailable symlink
  privilege (no permission changes), and POSIX shell syntax (Linux-only).
- Three new suites: **106 passed, 27 subtests passed**, no skips on normal
  Windows3.13.9 outside the sandbox with disposable fixtures outside the code
  tree. Includes ACTUAL Windows two-root copy/verification, native source write-
  sharing denial (error32), and read-only DACL admission. No existing ACL changed.
- Strict mypy passed for five modules (new copy, migration, capacity, source gate,
  bootstrap). Pyflakes passed new source/tests. Imported frozen helper's seven
  Linux-target errors remain open, not suppressed or called clean.
- Capacity SQL ran only in-memory PGlite using synthetic schemas; native source
  catalog permissions and actual capacity have NOT been measured by those tests.
- New copy tests cover private-parent inheritance/exposed principals, exact two
  roots, zero-byte/empty entries, scope/bounds, late source/destination additions,
  content drift, partial writes, disk full, externally anchored manifest and
  attempt-marker replacement/hardlinks/content mutation. Control files stay
  bound/read-held through completion. WAL/lock bytes are preserved, never opened
  as SQLite or promoted to integrity/restore/custody evidence.
- Cipher-copy checks bind both held file identities, exact externally anchored
  bytes/hash and the observed destination volume digest. They reject same-volume
  copies and identity substitution; a volume digest is not physical independence,
  encryption verification or authenticated custody. Error projection is bounded.
- Independent inspection found four first-draft issues and two control-handle
  gaps, then a verifier source-scope boundary gap. They were fixed and regressions
  added, including refusal before payload reads and metadata-only cipher probes.
  Final independent closure is
  recorded separately; builder test counts are not independent reruns.
- First disposable Linux run:317 passed/11 failed/3 skipped. The portable test
  adapter unintentionally used a512MiB tmpfs against the unchanged1GiB native
  free-space guard. Its fixture now supplies explicit synthetic capacity; the
  full-disk tests still inject zero and native Windows tests retain actual disk
  measurements. No production capacity check was relaxed.
- Corrected complete Linux rerun: **328 passed, 3 skipped, 27 subtests passed**,
  Python3.13.9 in an existing disposable image, no networking, read-only public
  source mount, no host ports/capture mounts, dropped capabilities, temporary
  writable fixture space. Skips: optional PGlite absent, two Windows-native tests.
  Complete Windows rerun remained **329 passed, 2 skipped, 27 subtests passed**.
  Linux strict mypy passed the same five maintained modules. This image is NOT
  the separately hash-locked36-package hosted environment or Python3.13.16;
  exact-final-SHA hosted checks on both supported patches remain mandatory.
- Both complete runtime/tool dependency audits returned exit0, without ignores
  or disabled audit paths. Locks and accepted native exporter are unchanged.
  The source export contains38 files and its static non-stdlib imports remain
  cryptography/packaging/pytest only; no UI/capture dependency was imported.

No actual Forward/ForwardOps root, installed capsule, private journal/config,
credential store, task, service, ACL or cloud/database state was changed. The
owner's saved75/0 capture remains an unsigned report until separately verified.
New exact-SHA hosted CI, owner-native acceptance, private cut, encryption,
off-PC readback, live DB export, custody/restore and retention remain unproven.

## Historical evidence for the earlier30-file release

## Current corrected package (privacy/governance/data boundary refresh)

Owner has approved the sibling route in principle and reports an earlier
26-file public export, not uploaded. Preserve that output unchanged/unaccepted.
This corrected package has 29 fixed source mappings plus the generated target
manifest: **30 target files**. Exact seed/base and final-SHA gates are unchanged.
No repository, branch setting, workflow variable or private backup was created.

Builder-verified on Windows Python 3.13.9 for this revision:

- Complete SEVEN-file sibling suite: **223 passed, 2 skipped**. The same two
  existing skip reasons below apply; no privilege change, new skip or bypass.
- Separate FOUR-file main-review annex's Python/SQL suite: **74 passed**, no
  skips. PGlite0.3.14 executed actual synthetic DDL triggers: automatic RLS at
  table creation, changed function definition with same identity, global trigger
  function outside the application schemas, enabled-state drift, exact positive
  and negative role access. This is NOT native PostgreSQL or Supabase acceptance.
- Combined eight-file selection: **297 passed, 2 skipped**. This is not the
  full application test suite and does not clear its unclassified failures.
- Strict mypy passed for five modules: standalone contract/launcher, pure
  artifact contract, pair watcher and restore-access comparator. Pyflakes passed
  those changed modules/tests. The unchanged helper's seven Linux-target errors
  are still open; no full Linux typing pass is claimed.
- Personal-path scan scope is ALL mapped public files, not only README. One
  personal home path was removed. New gate rejects literal home-profile paths
  before destination creation and during staged/final source verification. It
  is not secret DLP or proof that all arbitrary identifying text is absent.
  The owner's actual first output was also read at its exact 26 allowlisted
  PUBLIC paths: all 25 payload hashes match its old manifest; only README had
  a literal personal home path. No old output, private input or original changed.
- Pure artifact projection passes exact-byte digest, size/bool/type bounds,
  unknown format/key, measurement conflict, incomplete native result and false
  authority-claim rejection tests. It does not read/attest physical artifacts.
- Optional daily whole-profile audit workflow remains variable-gated OFF;
  delivery and scheduling have not been commissioned or proven.

Independent checker found the initial privacy fixture itself had literal POSIX
home paths. It was fixed with split synthetic literals and an actual complete-
mapping privacy regression. Separate event-trigger review found no blocking
defect; its suggested actual body-change/outside-schema runtime cases were
added and passed in PGlite. The checker separately exercised all trigger-field
drift/rejection cases in memory, not the builder's entire test suite.

Final current evidence:

- Maintenance-update regressions added after that first corrected test run;
  separate full candidate/prior-release checks retain the exact inert-seed and
  final-SHA rules. No committed update rehearsal is claimed.
- Fresh complete runtime AND complete installed tool/test audits PASSED,
  without ignores or disabled dependency resolution. The first sandboxed
  attempts stalled/time-limited and were NOT counted as passes. A bounded
  rerun outside the sandbox, with user pip configuration disabled and public
  PyPI explicitly selected, passed both. These are point-in-time public advisory
  observations, not a substitute for exact-SHA hosted CI or pre-export audit.
- Dedicated 36-package tool environment pip check passed. No new dependency,
  changed native tool hash, CA assumption or installed capture environment.
- Separate existing capture-preservation helper's synthetic Windows rehearsal:
  **40 passed, 3 skipped, 28 subtests passed** outside the sandbox with fixtures
  outside the code tree. Earlier sandbox hard-link/junction failures and an
  incorrect in-code-tree fixture location are preserved in the handoff. No
  source/ACL change, private-state copy or complete-image acceptance occurred.
- Corrected 30-file public distribution is staged in a NEW disposable unborn
  repository, no commit. Full exported seven-file suite, complete public privacy
  scope, all Python lint, exact-empty-tree checker and whitespace gate are
  rechecked after this evidence refresh. The final source/target manifest hashes
  are not embedded in a payload (which would create a circular self-hash).

All historical results below describe
the earlier package, not 30-file exact-SHA hosted CI. No final sibling commit
exists; Linux execution, new hosted checks, native acceptance, capture off-PC
copy, real export, authenticated custody and typed restore remain unverified.

## Historical first 26-file package — not current publication output

This is a new release unit, not a passing application audit. No owner repository,
setting, private backup, installed capture or system service was changed.

## Builder verified on Windows Python 3.13.9

- New runtime venv created inside the workspace lab, without pip and without
  system site packages. Complete hash-checked binary install succeeded: exactly
  cryptography 50.0.1, cffi 2.1.1, pycparser 3.0, packaging 26.3. Pip check passed.
- Separate new tool/test venv: complete 36-distribution hashed install and pip
  check passed. No Streamlit/Pillow/UI/capture packages installed in either.
  Existing root test environment and the installed capture were not upgraded.
- Ordinary full runtime requirement audit passed: NO KNOWN VULNERABILITIES.
  Ordinary complete installed tool/test environment audit also passed. No
  ignored IDs, disabled dependency resolution or altered app audit command.
  These are point-in-time advisory checks, not guarantees against future CVEs.
- Public wheel metadata supplied frozen Windows AMD64/Linux x86_64 CPython-3.13
  hash anchors. Actual Linux-target 3.13.16 binary dependency dry-run passed for
  the full 36-package tool lock. This is resolution/download, not Linux execution.
- Six bundled test files in the source workspace: 185 passed, 2 skipped. Skips:
  Windows POSIX shell-parser gate and absent symlink privilege. No new skips,
  privilege/ACL change or fallback. This is not the full application suite.
  The COMPLETE six-file suite was also run from the exported, staged 26-file
  distribution in its clean dedicated 36-package environment: 185 passed,
  2 skipped. All exported Python files/tests passed pyflakes. The initial
  exact-empty-tree staging checker and whitespace gate passed; no commit made.
- Pyflakes clean for new/changed modules/tests. Strict mypy passed for the four
  new/review modules on Windows. Linux-target strict checking reproduces SEVEN
  existing errors in the unchanged archive_preservation_inventory.py helper:
  Windows ctypes/msvcrt/O_BINARY stubs and Any return. Those errors remain open;
  do not label the full Linux-target type closure clean or hide them with ignores.
- -I -S -B launcher and Windows PowerShell watcher previews passed, reporting
  zero input/network/private-state/settings/task/credential operations. The
  public once-check made three requests, returned UNCHANGED_BLOCKED, candidates
  [], and evaluated Win/Linux on both 3.13.9 and 3.13.16. No popup was displayed,
  no watcher installed or started as a recurring/background process.

Tests cover: partial streams, stderr redaction, timeouts, child teardown/startup
failure, bounded output, unknown exit, pinned tools/CA, directory guarding,
external source SHA, strict seed tree, modes/extra/ignored files, source/hash/index
drift, no profile fallback, exclusive exporter output/partial retention, complete
runtime metadata, synthetic candidate/backport/marker/advisory/error cases,
malicious gate non-execution before authentication, ordered bootstrap dispatch.
The successful order test is mocked, not a real committed deployment rehearsal.

## Independent checker versus builder

Independent source review raised Git replacement-object/configuration, ignored
file/import boundary, gate-before-authentication and site-preflight concerns.
The code now disables replacement/graft/config influence, rejects ignored files,
authenticates gate source against the external commit before executing source
bytes (no .pyc import), and uses -I -S -B for preflight and bootstrap. Tests were
added; final review and exact exported-tree closure are reported separately.
The checker did not run native/product/private/hosted actions. Do not present
builder test counts as independent reruns.
Its final bounded source inspection found no remaining actionable finding;
independent staged closure verified all 25 source mappings, 26 target additions,
manifest/index/worktree consistency, regular modes, no extras and whitespace.
Documentation-only evidence refreshes afterward are rehashed and byte-checked;
they are not another independent test run or exact-final-SHA hosted result.

## Owner-reported, not reclassified as builder verification

PR57 exact 022e815: 7244 passed / 277 skipped / 76 subtests on Linux, certifi clear,
CodeQL/scanning/resilience green; full app audit failed on Pillow. Today's final
scheduled poll/audit result0 and saved report75/0 are owner-reported unsigned
claims, not journal or remote custody verification. Preservation generation1 signature and
contained eight-batch structural result remain the prior owner reports, not new
custody/restore facts from this work.

## Not verified / still required

- Actual separate repository/seed, exact target seed SHA, final source
  commit, hosted backup Quality/resilience/CodeQL/scanning on that SHA.
- Actual clean Linux execution on either patch; full isolated source-to-runtime
  startup on a real committed checkout (CI includes preview-only proof step).
- Native Docker ten-case run and Windows directory drill on the new exact tree.
- Native tool/DLL security, owner-supplied CA/tool pins, current DB backup facts/
  capacity, real opaque export and encrypted independent generation custody.
- Same-generation typed restore, cross-batch conflicts, ACL/API equivalence,
  cold-reader/writer integration and retention. Deletion stays unauthorised.
- Full application Windows failures/WinError 5; Package A Linux typing errors;
  operational/calendar/alert and research gates listed in the decision memo.

No Git commit/push/merge, hosted configuration, source database access, private
credential read, sealed research data inspection, clock/ACL/service/task change,
capture or audit invocation, deletion, real training or trading action occurred.
