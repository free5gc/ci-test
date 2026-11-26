#!/bin/bash

##########################
#
# This script is used for update nrf configuration as oauth enabled / disabled
#
##########################
#
# usage:
# ./script/oauth.sh <-e | --enable | -d | --disable>
#
# e.g. ./script/oauth.sh -e
#
##########################

usage() {
    echo "usage: ./script/oauth.sh <-e | --enable | -d | --disable>"
    echo "  -e, --enable  : enable oauth in NRF configuration"
    echo "  -d, --disable : disable oauth in NRF configuration"
}

if [ $# -ne 1 ]; then
    usage
    exit 1
fi

case "$1" in
    -e|--enable)
        FROM="false"
        TO="true"
        ACTION="enabled"
    ;;
    -d|--disable)
        FROM="true"
        TO="false"
        ACTION="disabled"
    ;;
    *)
        usage
        exit 1
    ;;
esac

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
NRF_CFG="${ROOT_DIR}/config/nrfCfg.yaml"

if [ ! -f "${NRF_CFG}" ]; then
    echo "Error: ${NRF_CFG} not found"
    exit 1
fi

sed -i -E "s/^([[:space:]]*oauth:[[:space:]]*)${FROM}/\1${TO}/" "${NRF_CFG}"

if grep -qE "^[[:space:]]*oauth:[[:space:]]*${TO}" "${NRF_CFG}"; then
    echo "NRF oauth ${ACTION} in ${NRF_CFG}"
else
    echo "Error: failed to set oauth to ${TO} in ${NRF_CFG}"
    exit 1
fi
