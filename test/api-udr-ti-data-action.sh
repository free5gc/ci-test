#!/bin/bash

##########################
#
# usage:
# ./api-udr-ti-data-action.sh <action> [ti_json_path]
#
# e.g. ./api-udr-ti-data-action.sh put json/ti-data-mec.json
# The optional JSON path is relative to the working directory; the default is json/ti-data.json beside this script.
#
##########################

set -e
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TI_DATA_JSON="${2:-$SCRIPT_DIR/json/ti-data.json}"

# ti data request
case "$1" in
    "put")
        curl -sS --fail-with-body --connect-timeout 5 --max-time 20 \
            -X PUT -H "Content-Type: application/json" --data-binary @"$TI_DATA_JSON" \
            http://udr.free5gc.org:8000/nudr-dr/v2/application-data/influenceData/1
        ;;
    "get")
        curl -sS --fail-with-body --connect-timeout 5 --max-time 20 \
            -X GET -H "Content-Type: application/json" \
            http://udr.free5gc.org:8000/nudr-dr/v2/application-data/influenceData
        ;;
    "delete")
        curl -sS --fail-with-body --connect-timeout 5 --max-time 20 \
            -X DELETE -H "Content-Type: application/json" \
            http://udr.free5gc.org:8000/nudr-dr/v2/application-data/influenceData/1
        ;;
    *)
        echo "error: invalid parameter"
        echo "usage: $0 [put|get|delete] [ti_json_path]"
        exit 1
        ;;
esac
