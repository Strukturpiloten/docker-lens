# ADR 0011: Preserve network-inspect active membership as source evidence

Status: accepted source contract; independent exact-lane native proof pending.

Docker network inspect `Containers` is a bounded active endpoint snapshot,
not authored topology or ownership. `NetworkObservation` retains its
container-ID map keys as protected runtime-assigned observations and each
entry's optional `Name` as a protected effective observation. The collection,
an individual entry, and its `Name` retain separate missing, null, empty,
present, and redacted states where those states can occur. Malformed values
and noncanonical container-ID keys fail with closed, value-free field errors;
the collection has the existing 4096-item limit.

This decoding adds no Engine request, selected root, or ambient container
inspection. An unselected container may appear as a protected network member
without becoming a selected or inspected container. Membership observed at
one instant cannot prove all stopped-container sharing, authored application
scope, resource ownership, or an atomic network graph. Consumers must decide
those questions separately, retaining explicit uncertainty and loss policy.

Offline tests establish only the representation and privacy boundaries. Before
a native compatibility claim, the exact four Engine lanes must independently
compare selected and unselected active members and a stopped-peer boundary
against direct network-inspect responses. Closed source-probe evidence must be
reviewed without changing historical manifests or target capability admissions.
