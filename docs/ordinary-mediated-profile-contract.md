# Ordinary mediated profile source contract

This is a test-only, source-only opt-in contract. It does not qualify native
execution, advertise a product capability, or provide a security sandbox.
`scripts/native-runner-apparmor.py:mediated_profile_bytes(name)` is a pure builder
for one fixed permissive prerequisite policy. It performs no parser, filesystem,
policy-loading, runtime, admission, or cleanup operation.

## Fixed policy and identity

The builder emits ABI 4.0, one ordinary profile declaration with the generated
name and fixed `flags=(attach_disconnected,mediate_deleted)`, and exactly thirteen
fixed family rules, in the order below. The flag order and absence of whitespace
after the comma are fixed bytes. They are path lookup flags, not caller-selectable
mode flags: ordinary enforce mode is required. The declaration
has no executable attachment, child profile, exec target, include, tunable,
rlimit, or caller-supplied policy fragment. It does not emit `change_profile` or
`change_hat` permissions. There is no selectable mode,
default-allow/unconfined/complain mode, or audit qualifier.

The only argument is a name matching the existing finite grammar:
`(?:dockerlens-127|boxferry-343)-upstream-rootless-[1-9][0-9]{0,19}-[1-9][0-9]{0,19}-[0-9a-f]{32}`.
Run and attempt are positive ASCII decimal strings of at most twenty digits,
without leading zeroes; the nonce is exactly thirty-two lowercase hex digits.
Uniqueness requires the caller's existing run/attempt/nonce custody. This pure
builder does not establish ownership or authorize loading just because a name
is syntactically valid.

## Reviewed explicit permission vector

The selected meaning is AppArmor **5.0.2**, source commit
`909affc32a13d14ae3a7ccf44d325ae63ce11baf`. The declared ABI 4.0 file is
2205 bytes, SHA-256
`e510bb8f6788b45e48de2f859a6f94a7b8416cbac5a1051814cfce925fa911bd`,
matching both admitted Containers architecture cohorts. The fixed rules are:

| Order | Rule | Reviewed meaning |
| ---: | --- | --- |
| 1 | `file,` | Ordinary file access and inherit-only execution (`ix`), owner and other |
| 2 | `capability,` | Full AppArmor capability permission mask |
| 3 | `network,` | Network permissions, including parser-generated Unix socket rules |
| 4 | `unix,` | Explicit Unix socket family |
| 5 | `dbus (bind, send, receive),` | Only ABI-advertised acquire/send/receive semantics |
| 6 | `mount,` | Mount permissions |
| 7 | `remount,` | Remount permissions |
| 8 | `umount,` | Unmount permissions |
| 9 | `pivot_root,` | Mount pivot-root permission, with no profile target |
| 10 | `signal (send, receive),` | Both signal directions |
| 11 | `ptrace,` | Read/trace/readby/tracedby permissions |
| 12 | `userns create,` | User-namespace creation permission |
| 13 | `mqueue (create, read, write, open, delete, setattr, getattr) type=posix,` | Exactly seven explicitly selected POSIX queue permissions |

ABI4 explicitly advertises all seven selected POSIX permissions, including
`delete`. Selecting type=posix excludes the separate SysV generator. No generic
mqueue rule, SysV queue rule, io_uring rule, or D-Bus eavesdrop permission is
emitted or claimed. Omission does not establish that an operation is denied or
mediated; kernel support or another permission path may differ.

The earlier all-rule candidate was blocked by pinned-source analysis: all-rule
unconditionally emits io_uring, ABI4 lacks that feature, and the unchanged
rule-not-enforced fatal-warning path exits 1. This is a static compatibility
finding, not a report of a parser or native run. The explicit vector is a newly
reviewed finite permission decision and is not claimed equivalent to all-rule.
An intermediate six-permission proposal incorrectly described POSIX delete as
absent from ABI4; the supported seventh permission is explicitly included here.

The selected classes add no self-directed profile/hat transition permission.
The ordinary file mask excludes the separate change-profile/change-hat bits;
inherit-only execution has no named transition target. This is a deliberately
permissive prerequisite inside the existing owned outer guest. Keeping its label
across execution may avoid another executable attachment's restrictions; it is
not a restriction-equivalence or least-privilege claim. The profile alone does
not grant Linux credentials, capabilities, namespaces, mounts, or loader authority.

Review the whole vector again before changing parser/source versions. Retain the
parser, ABI, cohort, namespace, policy-v9 and interpreter fingerprints and every
existing warning selector, fatal category, no-load/config/cache and isolation
guard. Do not override features, broaden ABI, suppress warnings, drop a class
dynamically or fall back. A live kernel can still lack a selected family: strict
compilation and fresh complete native behavior/cleanup qualification remain
required. These tests check source bytes, identity boundaries and exclusions;
they neither emulate parser expansion nor prove runtime enforcement or denial.
Maximum policies are 422 and 420 bytes for the DockerLens and BoxFerry prefixes,
within the existing 1024-byte consumer bound.

## Fixed path flags and conditional self-exec reasoning

[ADR 0052](decisions/0052-mediated-disconnected-path-flags.md) supersedes only the
previous flag-free declaration. The body, ABI4, name grammar and single-argument
interface stay fixed. No consumer selects the flags or changes policy bytes
locally. The pair adds exactly 44 ASCII bytes. Path attachment here means
connecting a disconnected pathname; it does not introduce an executable
attachment expression, profile transition or alternate label.

The source-supported candidate addresses an earlier path lookup, not a missing
exec permission: the bare file rule already includes inherit-exec. In reviewed
RootlessKit v0.14.4/Go 1.19.7 sources, self-exec through `/proc/self/exe` follows
creation of a new mount namespace. The examined upstream Linux v7.0 code retains
the executable file's original mount reference while copying the filesystem
namespace. Procfs follows that original path; AppArmor may identify the mount as
outside the current namespace and refuse it before matching file permissions.
A deleted executable or memfd is not required by that source explanation.

This remains conditional. The examined upstream kernel is not established as
the exact source of the admitted Ubuntu Azure 7.0.0-1017 build, and the failed
task's actually enforced profile and exact executable/source correspondence have
not been proved. A RootlessKit parent
fork/exec-self permission message alone cannot distinguish clone, unshare, execve
or the responsible security mechanism: Go can report those startup errors through
the same wrapper. No audit attribution or successful execution of this candidate
is claimed.

The pair deliberately preserves one examined deleted-dentry guard across an
explicit serialization boundary:

| Declaration | Parser 5.0.2 serialization | Examined upstream v7.0 effective mask | Unlinked positive dentry guard |
| --- | --- | --- | --- |
| Historical declaration without path flags | `path_flags` omitted | `0x20000` | Continues pathname mediation |
| `attach_disconnected` alone, not selected | Explicit `0x00004` | `0x00004` | Returns ENOENT |
| Fixed paired candidate | Explicit `0x10004` | `0x10004` | Continues pathname mediation |

Parser 5.0.2 names its `0x10000` bit `mediate_deleted`; the examined kernel calls
that bit `PATH_DELEGATE_DELETED`, while its omitted-field default
`PATH_MEDIATE_DELETED` is `0x20000`. The particular lookup guard accepts either
bit. Thus the pair preserves **that guard's result**, not a numeric mask or all
downstream semantics. Absence of the explicit parser flag did not mean deleted
paths were previously unmediated. Do not describe the pair as globally equivalent
to the previous declaration or use its text as proof of actual kernel behavior.

Disconnected-path connection expands pathname reachability and can introduce
pathname aliases. The existing all-file permissions and inherited execution
explain the permission selection, but do not remove that behavioral expansion
or establish sandbox safety. This remains one permissive disposable-runner test
prerequisite with exact generated enforce-label and ownership requirements.

Fresh qualification is on hold: verify actual pinned parser serialization and
admitted-kernel interpretation, connected/deleted and namespace-disconnected
self-exec boundaries, then actual postexec held-task label, original workloads
and complete private cleanup/unload across every affected ordinary/systemd row,
including Docker 20.10 on both supported architectures. A disappeared error,
compile or single repaired row is insufficient. Retain fatal warnings, all pins,
budgets, early-exit and label refusals, and the existing absence-before-unload
authority. No fallback, host policy change, new cleanup power or audit collector
is implemented by this source candidate. The active legacy 4.0.1 path stays
byte-identical and is not switched to this builder.

## Legacy callers and dependency ownership

The existing `profile_bytes`, `loaded`, and `RunnerProfile` remain unchanged.
They retain the fixed userns/unconfined policy, exact unconfined registry/task
expectations, parser 4.0.1 guards, lifecycle and receipts. The new builder is not
wired into any active DockerLens command or consumer automatically.

The caller inventory originally recorded with ADR 0051 is retained as historical
source-custody context below. This declaration-only candidate changes no recorded
consumer pin or authorization. A new consumer opt-in requires a real immutable
reviewed producer commit and actual source-closure sizes/hashes; historical
receipts and earlier source or native observations do not qualify these bytes.

| Owner | Existing use | This change |
| --- | --- | --- |
| DockerLens | `RunnerProfile` policy hashes/write; `native-outer-runtime.sh`, `native-outer-command.sh`, `native-conformance.sh` orchestration/receipts | Keep legacy builder and behavior |
| BoxFerry | Reviewed SDK closure in `reviewed-docker-consumer-authorizations.json`, `docker-application-contract.py`, `reviewed-docker-consumer-authorization.py`; application receipt validator | Keep sealed source authorization, helper hash and legacy receipt expectations |
| Containers | `docker_userns_policy_source.py` and sealed `docker_userns_custody_child.py` call `module.profile_bytes`; `docker-userns-policy-source.json` commits source files | Keep current immutable source and invocation until separate opt-in |

No dependency pin, parser pin, image definition, extraction path, approval rule,
or Renovate owner changes here. The 5.0.2 source above is a semantic review
reference, not a new installed/downloaded software definition. The separately
managed Containers source record retains its existing source/parser ownership
and manual review; BoxFerry's exact reviewed SDK authorization remains sealed.
Adding this source function does not qualify a changed SDK closure for either
consumer. A source commit and each affected file's actual size/hash must be
reviewed and bound when a consumer later opts in.

## Consumer opt-in and qualification still required

Containers' separate integration must select this exact builder in both its
policy-source path and immutable sealed child, update the child's source/module
guards, canonical source commit and all file sizes/hashes, admission commitment,
bootstrap/helper closures, and policy-byte bound if necessary. Its fixed
contract must require the generated name and exactly **enforce** mode in registry,
held-task, diagnostic/receipt, and unload checks. Historical receipt validation
and bare-unconfined bootstrap actor checks remain separately discriminated.
There is no acceptance of both policy modes, foreign RootlessKit labels,
qualified/stacked labels, or a matching component inside another label.

Preserve creation-bound identity, exact image/configuration custody, executable
measurements, task/pidfd, UID, cgroup and namespace checks, expiry owner and all
budgets. Source/hash substitutions, stale identities, wrong labels, collisions,
partial loads and failed readback must retain refusal and no cleanup authority.
Only complete existing held-task binding can grant attachment; only proven exact
guest/task/cgroup absence can permit the existing one-owned-profile unload.
Do not add foreign-profile cleanup, wildcard removal, fallback, or recovery of
historical retained leases.

Independent review and complete producer and consumer source gates precede
trusted native qualification against both exact immutable sources. A successful
compile, loaded registry entry, configured profile, or one repaired row does not
qualify runtime behavior. Fresh native evidence must bind the exact generated
enforce label after RootlessKit exec and subsequent held-task checks, native
userns/UID-helper/engine behavior, the complete affected ordinary-image and
systemd matrix on its already supported architectures, and terminal cleanup.
An attachment-cause claim additionally needs bounded read-only evidence of the
relevant loaded attachment and executable on that same host. No host attachment
change or additional native experiment is authorized by this source contract.

## Reference provenance

The review used read-only upstream source at
`https://gitlab.com/apparmor/apparmor/-/raw/909affc32a13d14ae3a7ccf44d325ae63ce11baf/`.
The reviewed upstream parser implementation declares GPL-2.0. It was used only as a semantic
reference; no upstream implementation was copied or mechanically translated,
and no upstream source or parser artifact is redistributed by this change.
No oracle/parser command or native experiment was run for these source controls.

| Reference path | Reviewed location | Bytes | SHA-256 |
| --- | --- | ---: | --- |
| `parser/all_rule.cc` | Historical rejected all-rule expansion, including implied io_uring | 4476 | `ed542adb0a6113e6e279073cbd745a5c542dcb2d3fa9c10743075508fad376f3` |
| `parser/parser_yacc.y` | 1216: file/ix; 1390–1415: mounts/D-Bus; 1628–1702: userns/POSIX queues; 1761: separate transitions; 1807: capabilities | 48156 | `152819632eac5a8c941b91d634db4a188eab5c7e4cd8a4743fa57b607cb668f0` |
| `parser/apparmor.d.pod` | 2159: self transitions; 2209: all-rule | 107173 | `254252e57181678c8bd6d5756cb8e866763ffb0afed1d1dec9ce23e30af7cae5` |
| `parser/immunix.h` | 50, 63–66: separate permission bits | 6919 | `aced01ebadc082ef5583aea9002ceb6068f241fedf1d1696393eb56606750a50` |
| `parser/parser.h` | Includes the reviewed permission definitions | 16385 | `b540f50d5995b13af72b2981d54438ac7ab81ab2c5e73f58a5d18bd83c01ccf2` |
| `profiles/apparmor.d/abi/4.0` | 34: seven POSIX queue permissions; declared family feature masks | 2205 | `e510bb8f6788b45e48de2f859a6f94a7b8416cbac5a1051814cfce925fa911bd` |
| `parser/mqueue.cc` | 75: POSIX type; 192: feature guard; 266: SysV type exclusion | 8948 | `6675ce8e1c277716a56e39517f97bb761f6fde6c22d0ced4188d8443455b3556` |

Additional reviewed source hashes are `parser/mqueue.h`
`641f125201ef1e1700cc4785ed50e56b74c0d229660e195297dbd91215191ca6`
(58: POSIX mask), `parser/dbus.cc`
`4b6cca2b07057579ada918b6a3a9d7d0b3704b91bdc7d46d43d68ceca985d0df`
(95: explicit versus default permissions), and `parser/rule.h`
`c13f1977c8d0a2c7bc3e24b7cef498d9262d776d8b5d348260c78409f4bcb892`
(104: no-op implied-rule default). Selected family headers do not override that
default; the reviewed network-to-Unix expansion is included above.

The path-flag review additionally used immutable source references: AppArmor
5.0.2 `909affc32a13d14ae3a7ccf44d325ae63ce11baf`, RootlessKit v0.14.4
`87d443683ac1e8aba4110b8081f15aaae432aaa2`, Go 1.19.7
`7bd22aafe41be40e2174335a3dc55431ca9548ec`, and upstream Linux v7.0
`028ef9c96e96197026887c0f092424679298aae8`. These are semantic references, not
changed dependency/tool pins. Relevant reviewed source hashes include:

| Source reference | Reviewed fact | SHA-256 |
| --- | --- | --- |
| AppArmor `parser/profile.h` 171, 204 | Initial flags and parser names | `3173ec38ffaae93260fae57ca4d2755b111dcb144b5484115aca3d0903a13f62` |
| AppArmor `parser/parser_interface.c` 522 | Explicit serialization versus omitted zero flags | `662882741f8bc916eaea3b0a55aaab7c279118fb9dc7815d6108b07a4f26519b` |
| Linux `security/apparmor/policy_unpack.c` 1238 | Omitted-field default | `078d121b60723ede5bc329a77e07ca95d2a30da51877e6b2036b8af24da59356` |
| Linux `security/apparmor/include/path.h` 14 | Numeric bit names | `2c6cd2fe0fb7ac0f3a3fe5386082d019800991ed45762e924ac34842dae2e0d6` |
| Linux `security/apparmor/path.c` 53, 125, 151, 160 | Disconnection and examined deleted-dentry guard | `0be893db0ca3551f10de6913bd8672ebbc07e7c9cd794659a18aad709d04a920` |

The specialist retrieved bounded unauthenticated immutable HTTPS source snapshots
and checked bytes/hashes; no oracle binary or parser command was executed for
this source candidate. AppArmor is GPL-2.0, RootlessKit Apache-2.0, Go BSD-3-Clause,
and Linux GPL-2.0-only with the syscall note where applicable. Research snapshots
remain private references: no oracle implementation is copied, mechanically
translated or redistributed in this change. No source version, installed tool,
software pin, Renovate ownership/extraction or consumer definition is changed.
