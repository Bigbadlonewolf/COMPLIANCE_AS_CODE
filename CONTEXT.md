# CONTEXT.md — Compliance-as-Code task routing

Read this when working in this project. `CLAUDE.md` has architecture/conventions detail; this routes by task type.

| Task | Go here | Also load |
|---|---|---|
| Write a new policy rule | `policies/<framework>/` (mirror existing file naming, e.g. `req_1.rego`) | `policies/lib/utils.rego` for shared constants; `CLAUDE.md`'s OPA Policy Conventions section |
| Write/run tests | `tests/<framework>/<name>_test.rego`, mirroring the policy file | **Must enumerate subdirs** — `opa test policies/ tests/pci_dss/ tests/soc2/ tests/nist_800_53/ -v`. Passing `tests/` directly loads `tests/fixtures/*.json` as OPA data and causes a merge error. |
| Run a single test file | `opa test policies/ tests/<framework>/<name>_test.rego -v` | — |
| Lint/syntax check | `opa check policies/ --strict` | — |
| Map a new/changed control to a policy | `docs/controls-mapping.md` | Confirm the citation (PCI DSS v4.0 / SOC2 TSC / NIST 800-53 Rev 5) matches an existing framework section |
| Evaluate a plan JSON locally | `./scripts/check-plan.sh tests/fixtures/<name>.tfplan.json` | Generate fresh plan JSON via `terraform plan` + `terraform show -json` if fixtures are stale |
| Evaluate one framework only | `opa eval -d policies/ -i tests/fixtures/noncompliant.tfplan.json '[m | m := data.pci_dss[_].deny[_]]'` | swap `pci_dss` for `soc2`/`nist_800_53` |

## Gotchas
- OPA `null` is a defined value — `not r.change.after.field` fails when `field = null` because the expression succeeds. Use explicit `== null` / `!= null` checks instead (see `CLAUDE.md` for the full list of affected fields).
- New policies use `import rego.v1`; legacy policies (`network_segmentation`, `access_control`, `encryption_at_rest`, `logging_monitoring`, `least_privilege`) use `import future.keywords` — both coexist without conflict.
