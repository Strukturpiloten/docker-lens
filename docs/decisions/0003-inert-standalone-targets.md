# ADR 0003: Render explicit standalone intent as inert Engine requests

Status: accepted implementation contract; native compatibility remains unproven.

This supersedes the target-setting and renderer placeholders in ADR 0002;
its capture and offline-evidence boundaries remain in force.

DockerLens accepts caller-authored target intent with named networks, named
volumes, and standalone containers. Container settings are typed: fixed TCP/UDP
port bindings, absolute bind paths or references to declared named volumes,
one declared bridge network, environment assignments, exec-form arguments,
exec-form health checks with at least 1 ms interval and timeout, and restart
policies. On-failure restart accepts zero as the Engine's unlimited-retry
value. A target field is never
inferred from a captured `Config.*` value. Swarm services, images built from a
context, start operations, and deployment are outside this contract.
An explicit Swarm orchestration request returns `UnsupportedOrchestration`.

The planner requires an exact validated daemon context or an exact offline
profile admitted by the reviewed capability catalog. Every used setting has a
distinct positive capability fact; missing, unknown, or unavailable facts
produce a value-free error identifying the resource, field, and capability.
The operation graph validates kinds, required references, and cycles. It
requires API 1.41 or later as a conservative schema floor. Rootful and rootless
claims stay separate because capability facts bind the exact mode and daemon
scope. Rootless host ports below 1024 are rejected regardless of a generic
publish claim. `PortPublish` gates both TCP and UDP requested shapes; it does
not prove either. A positive native record must cover every admitted protocol
and port shape for the exact mode and version, or the capability contract must
be narrowed first. Pure planner tests are not native compatibility evidence.

The renderer produces newline-delimited JSON records containing the POST
method, versioned Engine API path, and native JSON body. It orders network and
volume creation before a dependent container. Names enter URL query strings
through percent encoding; authored strings enter JSON through explicit
escaping. Health checks use the `CMD` array form, never `CMD-SHELL`. The
artifact is protected bytes with redacted `Debug`; only an explicit caller
read of `bytes()` reveals authored values. This crate has no executor,
transport, file writer, image builder, or deployment method.

Independent native conformance must verify these request shapes against each
claimed Engine release, API version, and daemon mode before compatibility is
claimed or a release gate is enabled. The public offline capability catalog
stays empty until reviewed native records are integrated.
