#!/bin/bash

##########################
#
# usage:
# ./api-webconsole-subscribtion-data-action.sh <action> <json_file>
#
# e.g. ./api-webconsole-subscribtion-data-action.sh [post|delete] json/webconsole-subscription-data-[offline|online].json
#
##########################

set -e

# get token
echo "Getting token..."

LOGIN_RESPONSE=$(curl -sS --fail-with-body --connect-timeout 5 --max-time 30 -X POST http://webui:5000/api/login \
-H "Content-Type: application/json" \
-d @json/webconsole-login-data.json)

TOKEN=$(echo "$LOGIN_RESPONSE" | jq -r '.access_token')

if [ -z "$TOKEN" ] || [ "$TOKEN" = "null" ]; then
    echo "Failed to get token!"
    exit 1
fi

if [[ ! "$TOKEN" =~ ^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$ ]]; then
    echo "Invalid token format!"
    exit 1
fi

echo "Token obtained successfully!"

# send subscription request (post)
echo "Sending subscription request..."

TOKEN=$(echo -n "$TOKEN" | tr -d '\n' | tr -d ' ')

# Extract IMSI from JSON file
IMSI=$(jq -r '.ueId' "$2" | sed 's/imsi-//')
PLMN_ID=$(jq -r '.plmnID' "$2")

echo "Using IMSI: $IMSI, PLMN ID: $PLMN_ID"

case "$1" in
    "post")
        SUBSCRIBE_RESPONSE=$(curl -sS --fail-with-body --connect-timeout 5 --max-time 30 -X POST "http://webui:5000/api/subscriber/imsi-$IMSI/$PLMN_ID" \
        -H "Content-Type: application/json" \
        -H "Token: $TOKEN" \
        -d @"$2")
        ;;
    "delete")
        SUBSCRIBE_RESPONSE=$(curl -sS --fail-with-body --connect-timeout 5 --max-time 30 -X DELETE "http://webui:5000/api/subscriber/imsi-$IMSI/$PLMN_ID" \
        -H "Content-Type: application/json" \
        -H "Token: $TOKEN" \
        -d @"$2")
        ;;
    *)
        echo "error: invalid parameter"
        echo "usage: $0 [post|delete]"
        exit 1
        ;;
esac

echo "Subscription request finished:"
echo "$SUBSCRIBE_RESPONSE"