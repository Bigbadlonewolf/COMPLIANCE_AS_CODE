# Control Coverage

`docs/controls-mapping.md` answers *what does this repo enforce, and what does each framework call it*. This document answers the harder question: **what does it not enforce, and why not.**

The distinction matters because a crosswalk showing eight green rows implies a denominator it never states. PCI DSS v4.0 has twelve requirements. This repo touches five of them, partially. Without that context the mapping reads as coverage when it is a sample.

**Legend**

| Status | Meaning |
| --- | --- |
| **Automated** | A policy denies on this in CI. Named in `docs/controls-mapping.md` |
| **Partial** | One sub-requirement is automated; the requirement as a whole is not |
| **Not addressable by IaC** | The requirement is about process, people, or runtime behaviour. No Terraform plan contains the evidence |
| **Addressable, not built** | Infrastructure-as-code *could* check this. It is not built. This is the honest backlog |

---

## PCI DSS v4.0 — twelve requirements

| Req | Title | Status | Notes |
| --- | --- | --- | --- |
| 1 | Network security controls | **Partial** | 1.3.2 automated (`req_1_network_controls`): sensitive ports open to `0.0.0.0/0`, `protocol = all` from the internet. Requirements 1.1–1.2 (documented rulesets, roles, approval of changes) and 1.4–1.5 are process |
| 2 | Secure configurations | **Partial** | 2.2.1 automated (`req_2_system_defaults`): public Cloud SQL IPs, buckets without uniform access or public access prevention. Vendor default credentials, inventory, and wireless are not addressable from a plan |
| 3 | Protect stored account data | **Partial** | CMEK at rest automated (`cmek_at_rest`, cited as 6.3.5). Requirement 3 proper — PAN masking, truncation, tokenisation, key custodian duties — is about *data*, and a Terraform plan contains none. This is the widest gap in the repo relative to what the requirement asks |
| 4 | Protect data in transit over public networks | **Partial** | Cloud SQL TLS automated (`tls_in_transit`, cited as 6.5.3). Certificate validity, cipher suite policy, and end-user messaging channels are not checked |
| 5 | Malicious software | **Not addressable by IaC** | Anti-malware deployment, currency, and scan evidence are runtime and endpoint concerns |
| 6 | Secure systems and software | **Partial** | 6.3.5 (CMEK) and 6.5.3 (TLS) automated. Secure SDLC, code review, patch timelines, and WAF tuning are process and application-layer |
| 7 | Restrict access by business need to know | **Partial** | 7.2.5 and 7.2.6 automated (`privileged_access`): primitive roles and public IAM members. Role definition, least-privilege *justification*, and access approval are process. A plan shows the binding, never whether it was warranted |
| 8 | Identify users and authenticate access | **Addressable, not built** | MFA enforcement via org policy, service-account key expiry, and password policy on Cloud SQL users are all expressible in Terraform. Not built |
| 9 | Restrict physical access | **Not addressable by IaC** | Google's responsibility under the shared model; evidenced by their attestations, not by this repo |
| 10 | Log and monitor all access | **Partial** | 10.2.1 (`req_10_logging`, pgAudit) and 10.3.2 (`sql_backups`, `object_versioning`) automated. Log review cadence, retention verification, and time synchronisation are not |
| 11 | Test security regularly | **Addressable, not built** | Not attempted. Vulnerability scanning cadence and penetration testing are operational, but scan-enablement config is expressible |
| 12 | Organisational policy and programme | **Not addressable by IaC** | Policy documents, training, incident response, third-party management |

**Summary:** 5 of 12 partially automated, 2 addressable but not built, 5 not addressable from infrastructure-as-code at all.

No requirement is fully automated. The honest sentence is *"eight specific sub-requirements across five requirements are enforced in CI"*, not *"PCI DSS coverage"*.

---

## SOC 2 TSC (2017)

Only the Common Criteria touched by this repo are listed. The Availability, Confidentiality, Processing Integrity, and Privacy categories are entirely out of scope.

| Criterion | Status | Notes |
| --- | --- | --- |
| CC6.1 — logical access controls | **Partial** | Public IAM members automated (`privileged_access.public_member`). The criterion also covers authentication, credential management, and access provisioning — none of which appear in a plan |
| CC6.3 — access based on roles | **Partial** | Primitive roles automated. Role *design* and periodic access review are process |
| CC6.6 — transmission security | **Automated** | Cloud SQL `ssl_mode = ENCRYPTED_ONLY` (`tls_in_transit`) |
| CC6.7 — data at rest | **Automated** | CMEK on Cloud SQL and buckets (`cmek_at_rest`) |
| CC7.1 — configuration monitoring | **Partial** | Key rotation automated. Continuous monitoring and change detection against *live* state are not — see What This Doesn't Prove |
| CC7.2 — anomaly detection | **Partial** | Object versioning and the Cloud Run monitoring-label check. Actual detection tooling is out of scope |
| CC8.1 — change management | **Partial** | SQL backups automated as a recoverability control. The change approval process itself is not evidenced here |

CC1–CC5 (control environment, communication, risk assessment, monitoring, control activities) are organisational and have no infrastructure counterpart.

---

## NIST SP 800-53 Rev 5

**Baseline: FedRAMP Moderate.** Selected because it is the common denominator for a cloud service handling regulated data, and because Low would exclude several controls this repo already enforces.

**Filtering criteria:** a control is in scope here only if (a) it is in the Moderate baseline, and (b) its implementation is visible in a Terraform plan for GCP. That excludes every control whose evidence is a document, a training record, or runtime telemetry.

| Control | Status | Notes |
| --- | --- | --- |
| AC-3 — access enforcement | **Partial** | Public IAM members automated |
| AC-6 — least privilege | **Partial** | Primitive roles automated. AC-6(1) through AC-6(10) enhancements are not |
| AC-17 — remote access | **Partial** | Remote-access ports from `0.0.0.0/0` automated (`ac_access_control`) |
| AU-2 — event logging | **Partial** | pgAudit flag automated |
| AU-9 — protection of audit information | **Partial** | Object versioning automated as tamper-evidence. Cryptographic protection and separate-system storage are not |
| AU-12 — audit record generation | **Partial** | `log_connections` and uniform bucket access |
| SC-8 — transmission confidentiality | **Automated** | Cloud SQL TLS |
| SC-28 — protection of information at rest | **Automated** | CMEK and key rotation |

**Eight controls of roughly 320 in the Moderate baseline.** That is a deliberately narrow slice and should be read as such. The controls chosen are the ones where a Terraform plan carries genuine evidence; the remainder are not weakly covered, they are not covered.

---

## Unmapped policy files

Five policy files carry checks that are **not yet in any coverage table above**, and this is outstanding work rather than a design decision:

`access_control`, `encryption_at_rest`, `network_segmentation`, `logging_monitoring`, `least_privilege`.

They contain AWS IAM wildcard checks, Cloud Run IAM conditions, AWS/Azure encryption rules, and secret-shaped environment variable detection. Their tests pass and they run in CI; what is missing is the citation trail. Until that is written, the checks are enforcement without evidence — which is the right way round to be incomplete, but still incomplete.

---

## Exceptions

Any control listed as **Automated** or **Partial** in the six shared controls can be suppressed for a specific resource by an entry in `exceptions/registry.yaml`, until that entry's expiration date. See [`docs/GOVERNANCE.md`](docs/GOVERNANCE.md).

An active exception is printed by the gate as a warning naming the approver and expiry, so coverage claimed here and coverage delivered on a given plan can be reconciled from the gate output rather than taken on trust.

Framework-local checks cannot be excepted.
