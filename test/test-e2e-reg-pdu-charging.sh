#!/usr/bin/env bash
set -euo pipefail

mode=${1:-}
case "$mode" in
    offline|online) ;;
    *) echo 'Expected exactly one charging mode: offline or online' >&2; exit 2 ;;
esac

fixture="json/webconsole-subscription-data-reg-pdu-charging-$mode.json"
./api-webconsole-subscribtion-data-action.sh post "$fixture"

cleanup() {
    local result=$?
    trap - EXIT
    if ! ./api-webconsole-subscribtion-data-action.sh delete "$fixture"; then
        if [[ $result == 0 ]]; then result=1; fi
    fi
    rm -f -- "$output"
    exit "$result"
}
output=$(mktemp)
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

echo "Testing $mode charging against a fresh Compose stack"
if ! (cd goTest && go test -count=1 -v -vet=off -run '^TestRegPduCharging$') > "$output" 2>&1; then
    cat "$output"
    exit 1
fi
cat "$output"
grep -Eq '^--- PASS: TestRegPduCharging \(' "$output"
