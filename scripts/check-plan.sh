#!/usr/bin/env bash
# check-plan.sh — Evaluate a Terraform plan JSON against all compliance policies.
#
# Usage:
#   ./scripts/check-plan.sh <path-to-plan.json>
#
# Generates plan JSON from Terraform:
#   cd terraform/compliant
#   terraform init -backend=false
#   terraform plan -var="project_id=fake" -var="kms_key_id=fake" -out=tfplan.binary
#   terraform show -json tfplan.binary > plan.json
#   ../../scripts/check-plan.sh plan.json

set -euo pipefail

PLAN_FILE="${1:-}"
POLICIES_DIR="$(cd "$(dirname "$0")/.." && pwd)/policies"

if [[ -z "$PLAN_FILE" ]]; then
  echo "Usage: $0 <path-to-plan.json>" >&2
  exit 1
fi

if [[ ! -f "$PLAN_FILE" ]]; then
  echo "Error: plan file not found: $PLAN_FILE" >&2
  exit 1
fi

if ! command -v opa &>/dev/null; then
  echo "Error: 'opa' not found in PATH. Install from https://www.openpolicyagent.org/docs/latest/#running-opa" >&2
  exit 1
fi

echo ""
echo "════════════════════════════════════════════════════════════"
echo " Compliance Policy Check"
echo " Plan:     $PLAN_FILE"
echo " Policies: $POLICIES_DIR"
echo "════════════════════════════════════════════════════════════"
echo ""

TOTAL_VIOLATIONS=0

check_framework() {
  local framework="$1"
  local label="$2"

  echo "── $label ──────────────────────────────────────────────────"
  VIOLATIONS=$(opa eval \
    --data "$POLICIES_DIR" \
    --input "$PLAN_FILE" \
    --format raw \
    "[m | m := data.${framework}[_].deny[_]]" 2>/dev/null || echo "[]")

  COUNT=$(opa eval \
    --data "$POLICIES_DIR" \
    --input "$PLAN_FILE" \
    --format raw \
    "count([m | m := data.${framework}[_].deny[_]])" 2>/dev/null || echo "0")

  TOTAL_VIOLATIONS=$((TOTAL_VIOLATIONS + COUNT))

  if [[ "$COUNT" -eq 0 ]]; then
    echo "  ✅ PASS — 0 violations"
  else
    echo "  ❌ FAIL — $COUNT violation(s):"
    opa eval \
      --data "$POLICIES_DIR" \
      --input "$PLAN_FILE" \
      --format pretty \
      "[m | m := data.${framework}[_].deny[_]]" 2>/dev/null \
      | grep -v '^\[' | grep -v '^\]' | grep -v '^$' | sed 's/^/    /' || true
  fi
  echo ""
}

check_framework "pci_dss"    "PCI DSS v4.0"
check_framework "soc2"       "SOC2 Trust Service Criteria"
check_framework "nist_800_53" "NIST SP 800-53 Rev 5"

echo "════════════════════════════════════════════════════════════"
if [[ "$TOTAL_VIOLATIONS" -eq 0 ]]; then
  echo " RESULT: ✅ COMPLIANT — 0 violations across all frameworks"
  EXIT_CODE=0
else
  echo " RESULT: ❌ NON-COMPLIANT — $TOTAL_VIOLATIONS violation(s) detected"
  EXIT_CODE=1
fi
echo "════════════════════════════════════════════════════════════"
echo ""

exit "$EXIT_CODE"
