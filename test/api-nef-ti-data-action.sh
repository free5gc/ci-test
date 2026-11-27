#!/bin/bash

##########################
#
# usage:
# ./api-nef-ti-data-action.sh <action> [ti_json_path]
#
# e.g. ./api-nef-ti-data-action.sh put json/ti-data-mec.json
# The optional JSON path is relative to the working directory; the default is json/ti-data.json beside this script.
#
# Traffic influence data is provisioned through NEF (3gpp-traffic-influence API) acting as an AF,
# instead of writing UDR directly. NEF stores it in UDR as AnyUE influence data.
#
# OAuth: when NRF has oauth enabled, this script registers the test AF to NRF and requests
# an access token (target NEF, scope 3gpp-traffic-influence) before calling NEF.
# When oauth is disabled, the token request fails and NEF is called without a token.
#
# actions:
# - put   : remove existing subscriptions of the test AF, then create one from the JSON file
# - get   : list subscriptions of the test AF
# - delete: remove all subscriptions of the test AF
#
##########################

set -e
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TI_DATA_JSON="${2:-$SCRIPT_DIR/json/ti-data.json}"

NRF_URI="http://nrf.free5gc.org:8000"
NEF_URI="http://nef.free5gc.org:8000"

# fixed identity of the test AF, so repeated runs update the same NRF profile
AF_ID="ci-test-af"
AF_NF_INSTANCE_ID="e04f8db7-a8f0-4df0-bd7f-3bf60fc1b0fa"
TI_SUBS_URI="${NEF_URI}/3gpp-traffic-influence/v1/${AF_ID}/subscriptions"

CURL_OPTS=(-sS --connect-timeout 5 --max-time 20)

# register the test AF to NRF and get an access token for NEF; prints nothing when oauth is disabled
get_token() {
    curl "${CURL_OPTS[@]}" -o /dev/null \
        -X PUT -H "Content-Type: application/json" \
        --data-binary "{
            \"nfInstanceId\": \"${AF_NF_INSTANCE_ID}\",
            \"nfType\": \"AF\",
            \"nfStatus\": \"REGISTERED\"
        }" \
        "${NRF_URI}/nnrf-nfm/v1/nf-instances/${AF_NF_INSTANCE_ID}" || return 0

    curl "${CURL_OPTS[@]}" \
        -X POST -H "Content-Type: application/x-www-form-urlencoded" \
        --data-urlencode "grant_type=client_credentials" \
        --data-urlencode "nfInstanceId=${AF_NF_INSTANCE_ID}" \
        --data-urlencode "nfType=AF" \
        --data-urlencode "targetNfType=NEF" \
        --data-urlencode "scope=3gpp-traffic-influence" \
        "${NRF_URI}/oauth2/token" | jq -r '.access_token // empty' 2>/dev/null || true
}

AUTH_HEADER=()
TOKEN="$(get_token)"
if [ -n "$TOKEN" ]; then
    AUTH_HEADER=(-H "Authorization: Bearer ${TOKEN}")
fi

# print the self URIs of all subscriptions of the test AF (none when the AF has no subscription)
list_sub_uris() {
    local body
    body=$(curl "${CURL_OPTS[@]}" "${AUTH_HEADER[@]}" -w '\n%{http_code}' "$TI_SUBS_URI")
    local code="${body##*$'\n'}"
    body="${body%$'\n'*}"
    case "$code" in
        200)
            echo "$body" | jq -r '.[]?.self // empty'
            ;;
        404)
            # NEF returns 404 when the AF has no subscription yet
            ;;
        *)
            echo "error: list subscriptions failed with status ${code}: ${body}" >&2
            return 1
            ;;
    esac
}

delete_all_subs() {
    local uris
    uris=$(list_sub_uris)
    for uri in $uris; do
        curl "${CURL_OPTS[@]}" --fail-with-body "${AUTH_HEADER[@]}" -X DELETE "$uri"
    done
}

# ti data request
case "$1" in
    "put")
        delete_all_subs
        curl "${CURL_OPTS[@]}" --fail-with-body "${AUTH_HEADER[@]}" \
            -X POST -H "Content-Type: application/json" --data-binary @"$TI_DATA_JSON" \
            "$TI_SUBS_URI"
        ;;
    "get")
        curl "${CURL_OPTS[@]}" "${AUTH_HEADER[@]}" "$TI_SUBS_URI"
        ;;
    "delete")
        delete_all_subs
        ;;
    *)
        echo "error: invalid parameter"
        echo "usage: $0 [put|get|delete] [ti_json_path]"
        exit 1
        ;;
esac
