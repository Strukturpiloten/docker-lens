# ADR 0006: Represent standalone network topology without claiming admission

Status: accepted target contract; new shapes await independent four-lane native evidence.

This supersedes ADR 0003's one-network, basic bridge target shape, not its
privacy, inert output, or reviewed-catalog boundary. A network intent has an
explicit identity and role (declared or application default) and is either an
authored bridge create or an external reference. Application default never
invents a Docker name. An external reference is a graph
`RequireExisting` step, emits no network-create request, and is retained as a
protected artifact prerequisite with an expected bridge driver. Neither the
graph nor the artifact asserts that the external network exists. BoxFerry
must verify identity and driver through read-only acquisition before any
isolated application rehearsal.

Created bridges carry typed internal/IPv6 flags, IPAM pools with validated
subnets, gateways, ranges and auxiliary addresses, closed bridge options, and
protected labels. Per-container attachments carry independent aliases and
explicitly authored IPv4/IPv6 addresses. Static addresses on a created
network require matching authored IPAM; decoder effective or
runtime-assigned addresses are never promoted here automatically. Host,
overlay and macvlan create modes are rejected. Duplicate networks, endpoints,
aliases, options and labels, invalid address families and unresolved graph
references fail before rendering. Network roles are metadata for an explicit
target identity, not an inferred source-authoring claim; only one application
default network may be declared in an intent.
Overlapping IPAM pools, duplicate reserved gateway/auxiliary addresses,
static addresses reused by two containers on one network, and static
addresses outside authored IPAM are rejected. Ordinary IPv4 subnet-base and
broadcast addresses are rejected for gateways, auxiliary addresses, and static
endpoints. IPv4 `/31` and `/32` CIDRs remain valid typed syntax, but bridge
planning reports `UnsupportedNetworkIpam` for those bridge-subnet sizes until #31
establishes exact Engine behavior; generic IPv4/IPAM capability facts cannot
admit them. A narrower `/31` or `/32` allocation range inside an ordinary
bridge subnet is a distinct shape and is checked against the parent subnet;
it does not bypass the parent-subnet rule or establish native support. Static
addresses on an external network remain unsupported until a separately verified
read-only prerequisite can establish its compatible IPAM.

Only the first attachment is embedded in the inert container-create request.
Each additional attachment is a distinct ordered graph step and inert
`networks/{name}/connect` request after container creation. This does not
assume that older Engines accept multiple endpoints at create time. The
renderer still has no transport or executor. The four historical catalog
records retain their twenty reviewed shapes. New network capabilities fail
closed for those profiles until #31 independently checks each request,
inspection, alias traffic, isolation, external ownership and exact Engine
version/mode lane, then review admits the corresponding closed shapes.
