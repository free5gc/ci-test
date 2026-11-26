#!/bin/bash

##########################
#
# This script is used for update nrf configuration as oauth enabled
#
##########################
#
# usage:
# ./oauth.sh
#
##########################


SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
NRF_CFG="${SCRIPT_DIR}/config/nrfCfg.yaml"

if [ ! -f "${NRF_CFG}" ]; then
    echo "Error: ${NRF_CFG} not found"
    exit 1
fi

sed -i -E 's/^([[:space:]]*oauth:[[:space:]]*)false/\1true/' "${NRF_CFG}"

if grep -qE '^[[:space:]]*oauth:[[:space:]]*true' "${NRF_CFG}"; then
    echo "NRF oauth enabled in ${NRF_CFG}"
else
    echo "Error: failed to enable oauth in ${NRF_CFG}"
    exit 1
fi
