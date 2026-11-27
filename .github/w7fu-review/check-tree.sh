#!/usr/bin/env bash
set -euo pipefail
git fetch --no-tags origin refs/heads/fix/units-w7-followups
head=$(git rev-parse FETCH_HEAD)
tree=$(git rev-parse FETCH_HEAD^{tree})
printf 'PR_HEAD=%s PR_TREE=%s PROBE_HEAD=%s\n' "$head" "$tree" "$(git rev-parse HEAD)"
test "$tree" = 550b35de890dffa950282bc960d6101a08fb7fee
printf '%s\n' .github/w7fu-review/check-tree.sh .github/w7fu-review/final-mutants.py .github/workflows/probe-w7fu-final.yml > "$RUNNER_TEMP/expected-probe-files"
git diff --name-only FETCH_HEAD HEAD | LC_ALL=C sort > "$RUNNER_TEMP/actual-probe-files"
diff -u "$RUNNER_TEMP/expected-probe-files" "$RUNNER_TEMP/actual-probe-files"
