# Verification

Run `./scripts/format-lint.sh --fix` for local formatting and lint feedback.
Run `./scripts/check-all.sh --check` for the complete scaffold gate: format,
Clippy, unit and documentation tests, policy tests, and documentation build.
`--fix` runs the same checks after formatting. The VS Code task calls the fast
format/lint script; PR and main CI call the complete gate.

The release validation workflow checks the explicitly supplied candidate SHA
against current `main`, runs the complete scaffold gate, and then invokes a
native conformance script that currently fails. A release cannot be validated
until #3 implements a genuine, independently reviewable rootful and rootless
Engine suite. No workflow in this scaffold publishes or deploys software.

The intended client platform is Linux. Mac client compatibility is not
validated by this scaffold. There is no macOS or Windows runner requirement.
