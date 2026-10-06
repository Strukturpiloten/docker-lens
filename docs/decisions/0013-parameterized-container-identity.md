# ADR 0013: Bound identity syntax and prove parameterized native semantics

Status: accepted target contract; expanded native proof and capability admission
remain pending under #86 and #39.

This refines ADR 0007's malformed-container-setting boundary. Its inert renderer,
protected values and exact-profile admission rules remain unchanged. ADR 0012's
volume-only candidate sequencing exception does not admit identity capabilities.

An authored user contains one principal or one user and one group separated by
exactly one colon. Each principal is a canonical decimal ID from zero through
`i32::MAX`, or an ASCII name matching `[A-Za-z_][A-Za-z0-9_.-]{0,31}`. Empty
components, extra separators, signs, leading-zero numeric spellings, whitespace,
control bytes, non-ASCII names and overflow fail with value-free errors. The ID
ceiling is a conservative library policy, not an Engine or namespace guarantee.
Supplementary groups use the same protected type but intent validation requires
one principal each, never `user:group`; their capability remains unadmitted.

Working directories retain their existing absolute, NUL-free UTF-8 contract.
The shared path type also carries device paths and is not globally tightened.
Planning neither reads image accounts nor establishes filesystem existence.
Omission delegates effective identity and directory to Engine/image merging.

`ContainerUser` and `ContainerWorkdir` mean parameterized native field semantics,
not that every image can successfully start every syntactically valid request.
Accounts/groups must exist where named, numeric IDs must fit the effective
namespace, an executable must be runnable, and the directory must be existing or
creatable and traversable. No host UID mapping, ownership/writability,
supplementary-group behavior or arbitrary-image success is promised.

Before raw identity shape mapping, require a complete private version-2 proof
with `identity_contract = "container-identity-v1"`. Ten independent CLI/renderer
pairs cover inheritance, numeric pair, numeric UID-only with a newly created
directory, named user, named pair, both mixed forms, missing user, missing group,
and an existing regular-file directory rejection. A pinned-image control must
first prove account/path premises. Positive cases require literal configured
fields, actual PID1 UID/GID/directory and successful exit; negative cases require
healthy transport and an attributed native cause, never timeout or arbitrary
nonzero status. Every attempted resource needs exact ownership, immutable-ID
cleanup and repeated exact absence before completion. The proof is bounded to
16 KiB and bound to candidate/lane/mode/API/run; legacy numeric-only markers are
retained as non-admission evidence.

Complete validated v2 proof may extend only the two singleton raw shape groups.
Historical evidence and reviewed-catalogue definitions stay immutable. A separate
sealed cohort requires fresh independently reviewed exact-source four-lane proof
and complete gates. Merge/release validation remains fresh for the final
candidate. BoxFerry's positive authored identity and loopback assertions must not
be weakened; identity completion does not complete ports or application migration.
No release, publication, deployment or execution authority is granted.
