#!/bin/bash

##########################
#
# This script is used for update nf configuration to route traffic through SCP
#
# enable : - AUSF advertises SCP (scp.free5gc.org) as its service address to
#            NRF, so consumers (AMF) discover SCP and send nausf-auth requests
#            through SCP, while AUSF still binds on its own address.
#          - AUSF uses a fixed nfInstanceId, and SCP trusts the same ID as the
#            nausf-auth producer (producerNfInstanceId). With OAuth enabled,
#            consumer tokens carry the AUSF instance ID as audience, which SCP
#            only accepts when it is configured here.
# disable: revert all of the above (AUSF advertises ausf.free5gc.org again and
#          gets a random nfInstanceId).
#
##########################
#
# usage:
# ./script/scp.sh <-e | --enable | -d | --disable>
#
# e.g. ./script/scp.sh -e
#
##########################

usage() {
    echo "usage: ./script/scp.sh <-e | --enable | -d | --disable>"
    echo "  -e, --enable  : route AUSF service through SCP"
    echo "  -d, --disable : let AUSF serve directly (no SCP)"
}

SCP_HOST="scp.free5gc.org"
AUSF_HOST="ausf.free5gc.org"
# fixed AUSF NF instance ID (UUID v4) shared by AUSF and SCP configuration
AUSF_NF_INSTANCE_ID="a2716152-8865-4fbf-9e9c-3fca95f2606c"

if [ $# -ne 1 ]; then
    usage
    exit 1
fi

case "$1" in
    -e|--enable)
        ENABLE=true
        TARGET_HOST="${SCP_HOST}"
    ;;
    -d|--disable)
        ENABLE=false
        TARGET_HOST="${AUSF_HOST}"
    ;;
    *)
        usage
        exit 1
    ;;
esac

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
AUSF_CFG="${ROOT_DIR}/config/ausfCfg.yaml"
SCP_CFG="${ROOT_DIR}/config/scpCfg.yaml"

for cfg in "${AUSF_CFG}" "${SCP_CFG}"; do
    if [ ! -f "${cfg}" ]; then
        echo "Error: ${cfg} not found"
        exit 1
    fi
done

# AUSF registerIPv4
sed -i -E "s/^([[:space:]]*registerIPv4:[[:space:]]*)[^[:space:]#]+/\1${TARGET_HOST}/" "${AUSF_CFG}"

# remove previous fixed IDs (keeps the script idempotent)
sed -i -E '/^[[:space:]]*nfInstanceId:/d' "${AUSF_CFG}"
sed -i -E '/^[[:space:]]*producerNfInstanceId:/d' "${SCP_CFG}"

if [ "${ENABLE}" = true ]; then
    sed -i -E "s/^configuration:.*$/&\n  nfInstanceId: ${AUSF_NF_INSTANCE_ID} # fixed NF instance ID, trusted by SCP (set by scp.sh)/" "${AUSF_CFG}"
    sed -i -E "s/^([[:space:]]*)- serviceName: nausf-auth.*$/&\n\1  producerNfInstanceId: ${AUSF_NF_INSTANCE_ID} # AUSF NF instance ID (set by scp.sh)/" "${SCP_CFG}"
fi

# verify
if ! grep -qE "^[[:space:]]*registerIPv4:[[:space:]]*${TARGET_HOST}" "${AUSF_CFG}"; then
    echo "Error: failed to set AUSF registerIPv4 in ${AUSF_CFG}"
    exit 1
fi

if [ "${ENABLE}" = true ]; then
    if ! grep -qE "^  nfInstanceId:[[:space:]]*${AUSF_NF_INSTANCE_ID}" "${AUSF_CFG}"; then
        echo "Error: failed to set AUSF nfInstanceId in ${AUSF_CFG}"
        exit 1
    fi
    if ! grep -A1 -E "^[[:space:]]*- serviceName: nausf-auth" "${SCP_CFG}" | grep -qE "producerNfInstanceId:[[:space:]]*${AUSF_NF_INSTANCE_ID}"; then
        echo "Error: failed to set nausf-auth producerNfInstanceId in ${SCP_CFG}"
        exit 1
    fi
    echo "SCP enabled: AUSF registerIPv4=${TARGET_HOST}, nfInstanceId=${AUSF_NF_INSTANCE_ID}"
else
    if grep -qE "^[[:space:]]*nfInstanceId:" "${AUSF_CFG}" || grep -qE "producerNfInstanceId:" "${SCP_CFG}"; then
        echo "Error: failed to remove fixed AUSF nfInstanceId"
        exit 1
    fi
    echo "SCP disabled: AUSF registerIPv4=${TARGET_HOST}, nfInstanceId removed"
fi
