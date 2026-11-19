#!/usr/bin/env bash
set -euo pipefail
set +x

enabled=$1
tmpdir=$(mktemp -d)
trap 'rm -rf -- "$tmpdir"' EXIT
pcf=http://pcf.free5gc.org:8000
nrf=http://nrf.free5gc.org:8000
scope=npcf-smpolicycontrol
realm="$pcf/$scope/v1"
protected="$realm/sm-policies/nonexistent-ci-oauth-test"
status=
failures=0

request() {
    : > "$tmpdir/headers"
    status=$(curl --silent --show-error --noproxy '*' \
        --retry 5 --retry-connrefused --retry-delay 1 --retry-max-time 30 \
        --connect-timeout 3 --max-time 8 --dump-header "$tmpdir/headers" \
        --output "$tmpdir/body" --write-out '%{http_code}' "$@")
}

expect_status() {
    if [[ "$status" != "$1" ]]; then
        printf 'FAIL: %s expected HTTP %s, got %s\n' "$2" "$1" "$status" >&2
        failures=1
    fi
}

challenge() {
    local label=$1 error=${2:-} required=${3:-} header
    local realm_pattern='(^|,)[[:space:]]*realm="http://pcf[.]free5gc[.]org:8000/npcf-smpolicycontrol/v1"[[:space:]]*(,|$)'
    local error_pattern='(^|,)[[:space:]]*error='
    local expected_error="(^|,)[[:space:]]*error=\"?${error}\"?[[:space:]]*(,|$)"
    local scope_pattern="(^|,)[[:space:]]*scope=\"?${required}\"?[[:space:]]*(,|$)"
    header=$(awk '
        /^HTTP\// { value="" }
        tolower($0) ~ /^www-authenticate:[ \t]*bearer[ \t]+/ {
            sub(/\r$/, ""); sub(/^[^:]*:[ \t]*[^ \t]+[ \t]+/, ""); value=$0
        }
        END { print value }
    ' "$tmpdir/headers")
    if [[ ! "$header" =~ $realm_pattern ]] ||
        [[ -z "$error" && "$header" =~ $error_pattern ]] ||
        [[ -n "$error" && ! "$header" =~ $expected_error ]] ||
        [[ -n "$required" && ! "$header" =~ $scope_pattern ]]; then
        printf 'FAIL: %s has an incorrect R17 Bearer challenge\n' "$label" >&2
        failures=1
    fi
}

token_request() {
    request --data-urlencode grant_type=client_credentials \
        --data-urlencode "nfInstanceId=$1" --data-urlencode "nfType=$2" \
        --data-urlencode "targetNfType=$3" --data-urlencode "scope=$4" "$nrf/oauth2/token"
}

authenticated_request() {
    # Keep the raw bearer out of curl command-line arguments and diagnostics.
    printf 'Authorization: Bearer %s\n' "$1" > "$tmpdir/auth"
    request --header "@$tmpdir/auth" "$protected"
    rm -f -- "$tmpdir/auth"
}

expect_handler() {
    expect_status 404 "$1"
    if ! jq -e '.cause == "CONTEXT_NOT_FOUND"' "$tmpdir/body" >/dev/null; then
        printf 'FAIL: %s did not reach the SM policy handler\n' "$1" >&2
        failures=1
    fi
}

request "$protected"
if [[ "$enabled" == false ]]; then
    expect_handler 'OAuth OFF, tokenless request'
    [[ $failures == 0 ]]
    exit
fi

expect_status 401 'missing token'
challenge 'missing token'
request -H 'Authorization: Bearer intentionally.invalid.token' "$protected"
expect_status 401 'invalid token'
challenge 'invalid token' invalid_token

token_request "$2" SMF PCF "$scope"
expect_status 200 'NRF token issuance'
token=$(jq -er 'select(.token_type == "Bearer" and .expires_in > 0) | .access_token |
    select(type == "string" and test("^[A-Za-z0-9_-]+[.][A-Za-z0-9_-]+[.][A-Za-z0-9_-]+$"))' "$tmpdir/body")
claims=${token#*.}
claims=${claims%.*}
while (( ${#claims} % 4 )); do claims+="="; done
if ! printf '%s' "$claims" | tr '_-' '/+' | base64 -d |
    jq -e --arg subject "$2" --arg scope "$scope" '
        .sub == $subject and .scope == $scope and (.aud == ["PCF"] or .aud == "PCF")
        and (.iss | type == "string" and length > 0) and .exp > now
    ' >/dev/null; then
    echo 'FAIL: unexpected NRF-issued JWT claims' >&2
    failures=1
fi
authenticated_request "$token"
expect_handler 'valid NRF token'
unset token

token_request "$3" AMF PCF "$scope"
expect_status 400 'AllowedNfTypes rejects AMF for SM policy'
if ! jq -e '.error == "invalid_scope"' "$tmpdir/body" >/dev/null; then failures=1; fi

token_request "$2" AMF PCF "$scope"
expect_status 400 'wrong requester NF type'
if ! jq -e '.error == "invalid_client"' "$tmpdir/body" >/dev/null; then failures=1; fi

token_request "$2" SMF NRF nnrf-disc
expect_status 200 'NRF-audience control token issuance'
other_token=$(jq -er '.access_token | select(type == "string" and test("^[A-Za-z0-9_-]+[.][A-Za-z0-9_-]+[.][A-Za-z0-9_-]+$"))' "$tmpdir/body")
authenticated_request "$other_token"
unset other_token
expect_status 401 'wrong audience'
challenge 'wrong audience' invalid_token

token_request "$3" AMF PCF npcf-am-policy-control
expect_status 200 'PCF same-audience, different-scope token issuance'
scope_token=$(jq -er '.access_token | select(type == "string" and test("^[A-Za-z0-9_-]+[.][A-Za-z0-9_-]+[.][A-Za-z0-9_-]+$"))' "$tmpdir/body")
authenticated_request "$scope_token"
unset scope_token
expect_status 403 'same audience, insufficient scope'
challenge 'same audience, insufficient scope' insufficient_scope "$scope"

request -H 'Content-Type: application/json' --data '{"amfStatusInfoList":[]}' \
    "$pcf/npcf-callback/v1/amfstatus"
expect_status 204 'valid tokenless AMF notification payload'

[[ $failures == 0 ]]
echo 'OAuth HTTP access-control checks passed'
