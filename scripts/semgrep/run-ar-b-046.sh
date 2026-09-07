#!/usr/bin/env bash
# AR-B-046 tripwire runner — the "absent/empty/unconfigured ⇒ permit" idiom sweep.
#
# Advisory by design: it prints every match so a reviewer can justify or fix each
# one, and only fails when SEMGREP_STRICT=1 is set. See the rule file header and
# audit finding AR-B-046 for why the idiom is dangerous and where it was fixed.
set -uo pipefail
cd "$(dirname "$0")/../.."

RULE="scripts/semgrep/ar-b-046-fail-open-defaults.yml"
TARGETS=(agent agent-cron agent-legacy)

if ! command -v semgrep >/dev/null 2>&1; then
  echo "AR-B-046: semgrep not installed — skipping advisory sweep (install: pipx install semgrep)"
  exit 0
fi

echo "AR-B-046: sweeping ${TARGETS[*]} for fail-open default idioms…"
if [ "${SEMGREP_STRICT:-0}" = "1" ]; then
  semgrep --config "$RULE" "${TARGETS[@]}" --no-git-ignore --error --quiet
else
  semgrep --config "$RULE" "${TARGETS[@]}" --no-git-ignore --quiet
  echo "AR-B-046: advisory only — review each hit (set SEMGREP_STRICT=1 to fail on any)."
fi
