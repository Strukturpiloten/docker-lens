# Failure-only rootless kernel window

The original nineteen-test native harness has one optional, read-only kernel
journal snapshot. It runs only after the existing exact RootlessKit self-reexec
line yields `permission_denied`, `operation_not_permitted`, or `ambiguous`, in
the admitted hosted Docker-outer/rootless-inner lane. Local Podman, rootful inner
lanes, missing startup evidence, and failed hosted admission never read the
journal. Both the shell and directly invoked helper enforce the canonical
hosted accident guard; environment values are not dispatcher authentication.
Trusted-main actor/head admission remains the coordinator's responsibility.

The harness holds one paired epoch-microsecond/BOOTTIME-nanosecond boundary
immediately before actual daemon create/start. Each realtime sample is bracketed
by two BOOTTIME reads; a span greater than 10 milliseconds or a reversed sample
refuses instead of widening the tolerance or retrying. The BOOTTIME midpoint
and realtime value are retained together. Failure does not renew that pair.
The helper binds the query end once and requests only current-boot kernel entries in that window,
using `journalctl --boot=0 --dmesg` with JSON output and explicit since/until
timestamps. Every record's realtime timestamp is independently checked against
the held bounds. Journal `_COMM` is neither a filter nor attribution evidence;
the parser inspects the `MESSAGE` AppArmor fields.

Before querying and after capture, parsing, and private-file cleanup, elapsed
wall time must agree with elapsed BOOTTIME from the original pair within a
fixed 100 milliseconds. The two bracketed samples contribute at most 10
milliseconds of midpoint uncertainty plus microsecond quantization; the fixed
100-millisecond allowance is conservative and never grows with lane age.
Forward or backward discrepancies beyond it, even within the 1800-second
sanity window, make the observation unavailable. Later clock sampling validates
only this mapping: it cannot move the held query end or trigger another query.
Normal clock slew may therefore conservatively refuse a long window. This is
not continuous clock monitoring: smaller discrepancies, or opposing changes
that cancel between samples, are not excluded. An unobserved result remains a
bounded journal-window observation, not universal absence evidence.

## Budgets, custody, and cancellation

The original live watchdog and at least five seconds of the original
1800-second lane budget are mandatory. The once-only whole helper is beneath
root-owned GNU `timeout` (three seconds TERM, 0.5 seconds KILL fallback), with
`sudo -n` before timeout when necessary. This covers environment setup, Python
initialization, collection, parsing, and private-file cleanup, not just the
journal subprocess. The wrapper independently checks elapsed boot time below
3.99 seconds and the original watchdog/window before releasing an observation.
There is no retry, refunded budget, renewed deadline, or promised cleanup reserve.

The journal subprocess has its own root-owned two-second TERM/0.25-second KILL
timer inside that envelope. Capture ends at the original 2.5-second cutoff;
Python's 2.75-second whole-operation alarm and repeated boot-clock checks are
advisory checks, not privileged containment. The outer GNU timer is authoritative.
Only the nine explicit non-secret hosted policy variables cross the whole-helper
environment boundary. Journal capture has the fixed PATH/LANG/LC_ALL environment
and one exact command/prefix policy, using the reviewed shared `CaptureContext`
without changes: 32 KiB per stream, 64 KiB aggregate, and no output reuse.
Private staging is removed before ordinary handoff. No raw journal output,
profile name, PID, path, or journal artifact is published or uploaded.

SIGINT/SIGTERM produce unavailable evidence and propagate 130/143 through the
existing lane traps. Timeout statuses 124/137 remain unavailable. Failed or
unknown child completion/cleanup cannot become an absence claim. Neither a
timer status nor cancellation proves root-child death; SIGKILL, blocked kernel
I/O, or host failure may prevent cleanup. Existing lane resource cleanup and its
uncertainty rules remain unchanged.

## Closed observation, not cause

The sole marker has fixed fields: `scope=job_window`, observation
`observed|unobserved|ambiguous|unavailable`, operation
`userns_create|exec|other|unknown`, and explicit errno
`permission_denied|operation_not_permitted|other|absent`.

Strict complete newline-delimited JSON rejects duplicate fields, partial
records, invalid types/encoding, out-of-window timestamps, oversized output,
access warnings even on exit zero, failed commands, and timeout/cancellation.
These are unavailable, never unobserved. Within valid JSON, incomplete or
conflicting AppArmor field evidence is ambiguous. Exact quoted `apparmor="DENIED"`
and exact quoted `comm="rootlesskit"` are required for a positive event.
Quotedness is retained during parsing: unquoted authority fields cannot prove
either an event or its absence. A DENIED record with missing, empty, malformed,
or noncanonical `comm` is ambiguous. Only a complete quoted ASCII task spelling
of one to fifteen bytes can establish a different task and support an unobserved
projection. A recognized audit envelope missing its AppArmor field, unsupported
AppArmor status spellings, and unquoted operation fields on a matching task
remain ambiguous rather than silently supplying a negative or operation claim. Explicit
`error`/`errno` fields are separate evidence; DENIED alone is **not** errno.
Multiple conflicting matching events remain ambiguous. A completed empty query
is only unobserved within this current-boot job window, not proof that a denial
never occurred. Wall-clock discontinuity or incomplete journal availability
cannot support a stronger claim.

The observation does not identify the exact failing PID, prove causation,
establish an effective AppArmor profile, or grant native compatibility. The
original startup error and failed lane status remain unchanged. No package
installation, extra native canary, sysctl write, profile change, or runtime
mutation is introduced.

## Consumers and dependency review

The canonical definition remains `scripts/native-conformance.sh`, consumed by
local execution and the unchanged `check.yml`, `native-validation.yml`, and
`release-validation.yml` native workflows. Local execution refuses this optional
journal query. The four lanes, nineteen exact test invocations, five image pins,
resource limits, and native cleanup remain unchanged. This diagnostic is not
added to BoxFerry's separate harness or the independent twenty-eight-test work.

Read-only Renovate review confirms the one existing native-image regex manager
still extracts the same five tag/digest pairs from the same canonical script;
its grouping and manual approval (`automerge: false`) remain unchanged. Cargo,
toolchain and GitHub Actions managers, extraction paths, workflow consumers,
historical evidence and pins are unchanged. No new software pin or duplicate
manager is needed. Journalctl, GNU timeout, sudo, and Python use the existing
version-selected Ubuntu 24.04 hosted image: there is no download or installation,
and no invented per-runner tool checksum. Its existing unavailable-integrity
and manual runner-image review exception still applies.

Hermetic tests exercise synthetic journal records and fake processes only.
They are not host observations or native qualification. Fresh exact-candidate
complete and four-lane gates and independent review remain integrator-owned.
The [systemd journal JSON format](https://systemd.io/JOURNAL_EXPORT_FORMATS/)
and [journalctl timestamp/filter interface](https://www.freedesktop.org/software/systemd/man/latest/journalctl.html)
were checked through Context7 against the upstream documentation; no oracle
implementation source was copied or translated.
