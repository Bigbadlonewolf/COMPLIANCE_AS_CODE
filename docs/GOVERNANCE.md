# Governance: risk acceptance and exceptions

A policy gate with no exception path is a gate people route around. A policy gate with an unbounded exception path is a spreadsheet with extra steps. This document describes the narrow thing in between, and states plainly what it does not cover.

---

## The position

**Every exception expires.** There is no permanent value, no `never`, no empty field that means forever. An entry without an `expiration_date` grants nothing, and an entry whose date has passed grants nothing — no cleanup job required, no reminder to ignore. This is the one property the mechanism is built around, because it is the one that decides whether a policy-as-code programme is still enforcing anything in eighteen months.

**Exceptions are scoped to one resource and one control.** `resource_address` plus `control_id`. There is no wildcard and no "exempt this whole module". An exception that covers a class of resources is indistinguishable from deleting the rule.

**Exceptions are visible.** Every active exception that touches a resource in the plan is printed by the gate as a warning, naming the approver, the expiry, and the justification. A suppressed finding and a finding that never fired are otherwise identical in a green build, and that ambiguity is how exception mechanisms rot.

**Losing the registry cannot weaken the gate.** `lib/exceptions.granted` is a partial function; when the registry is not loaded it is undefined for every input, so every control denies as normal. Forgetting `--data` fails closed.

---

## Requesting an exception

1. **Fix it instead, if you can.** Most findings are a two-line Terraform change. An exception costs a PR, a review, and a diary entry six months out; the fix usually costs less.

2. **Add an entry to `exceptions/registry.yaml`:**

   ```yaml
   exceptions:
     - exception_id: EXC-2026-004
       resource_address: google_storage_bucket.public_docs_site
       control_id: object-versioning
       justification: >-
         Static documentation site rebuilt from source on every deploy. Versioning
         would retain every superseded asset indefinitely, and the bucket holds no
         data that is not reproducible from the repository that generates it.
         Tamper-evidence comes from that repository's history.
       approved_by: lanre.oluokun
       approved_date: "2026-07-28"
       expiration_date: "2027-01-28"
   ```

   Quote the dates. Unquoted, YAML deserializes them as date objects and the validator rejects them.

3. **Write the justification for someone who was not in the conversation.** It should survive being read aloud by an auditor. "Temporary", "blocking the release", and "will fix later" are not justifications — they are schedules, and the `expiration_date` field already records the schedule.

4. **Pick an expiry you can defend.** The default is 90 days. Longer than six months needs the justification to explain why the underlying condition will not have changed.

5. **Open a PR.** CI validates the registry shape, the `control_id`, the date formats, and `exception_id` uniqueness, and reports entries that have already expired.

## Renewing

There is no renewal. Editing a date in place turns an expiry into a formality — the whole value of the mechanism is that lapsing is the default and continuing requires a decision.

Write a new entry with a new `exception_id` and a fresh justification, and delete the old one. If the justification is still true, this costs two minutes. If it is not, you have found the thing the expiry was for.

`exception_id` values are never reused.

---

## Valid control IDs

Only the six shared controls in `policies/controls/` are exception-able.

| `control_id` | Covers |
| --- | --- |
| `cmek-at-rest` | CMEK on Cloud SQL instances and storage buckets |
| `key-rotation` | KMS keys rotate, and at least annually |
| `object-versioning` | Object versioning on storage buckets |
| `privileged-access` | Primitive roles and public IAM members |
| `sql-backups` | Automated backups on Cloud SQL |
| `tls-in-transit` | `ssl_mode = ENCRYPTED_ONLY` on Cloud SQL |

One exception suppresses the finding across **every framework that cites that control**. Excepting `privileged-access` on a resource removes the PCI DSS 7.2.5, SOC 2 CC6.1, and NIST AC-6 failures together, because all three attach citations to the same detection logic. That is the intended behaviour of the shared-control architecture — but it means an exception is broader in citation terms than it looks, and the justification should be written knowing that.

---

## What this does NOT cover

**Framework-local checks are not exception-able.** The AWS and Azure encryption rules, the secret-shaped-environment-variable detector, and the network segmentation checks live outside `policies/controls/`, have no `control_id`, and cannot be excepted. Adding them means giving each a control ID and routing it through the same helper. Until then, the only way past one of those is to fix the finding or delete the rule — and deleting the rule is visible in a diff, which is the point.

**There is no approval workflow.** `approved_by` is a string in a YAML file. In a single-operator repository it records intent; it is not evidence, and this document will not pretend otherwise. Real approval evidence is the PR review and its commit history, which is why exceptions go through a PR rather than a direct commit. In a team setting, `approved_by` should be checked against a group membership the requester cannot edit — that is not built here.

**There is no ticketing integration, and no expiry notification.** Nothing emails you when an exception is about to lapse. CI reports already-expired entries on every run, which means you find out at the next build rather than in advance. That ordering is deliberate — an expired exception has already stopped suppressing anything by the time it is reported, so the report is hygiene, not an incident.

**Exceptions are not audited over time.** The registry shows what is exempt now. Reconstructing what was exempt last March means reading git history. For an audit trail that an examiner would accept, that history needs to be in a store the requester cannot rewrite.

---

## Running the gate with the registry

```bash
# Conftest — the CI gate
conftest test plan.json --policy policies --data exceptions/registry.yaml --all-namespaces

# OPA — one framework
opa eval -d policies/ -d exceptions/registry.yaml -i plan.json '[m | m := data.pci_dss[_].deny[_]]'

# Validate the registry itself
opa eval -d exceptions/ 'data.exceptions_validate.errors'
```

Pass `exceptions/` as a **relative** path. Given an absolute path, OPA derives the data path from the path itself — on Windows the drive letter becomes a data segment, `data.exceptions` is undefined, and every exception silently stops applying. Fails closed, but confusingly.
