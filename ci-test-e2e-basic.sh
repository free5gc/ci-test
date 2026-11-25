#!/bin/bash

##########################
#
# usage:
# ./ci-test-e2e-basic.sh -t <test-name> <-b> <-l [datetime]>
#
# e.g. ./ci-test-e2e-basic.sh -t TestRegPduCharging <-b> <-l>
#
# -b, --build          : use the build compose file
# -l, --log [datetime] : save docker compose logs to log/<datetime>/e2e-basic/<test-name>/
#                        (datetime defaults to now, format YYYYMMDD-HHMMSS)
#
##########################

TEST_POOL="TestRegPduCharging"

COMPOSE_FILE="composes/build/docker-compose-e2e-basic.yaml"
CI_COMPOSE_FILE="composes/docker-compose-ci-e2e-basic.yaml"

TIMEOUT=1800 # 30 minutes
CI_TIMEOUT=300 # 5 minutes

TARGET_COMPOSE_FILE="$CI_COMPOSE_FILE"
TARGET_TIMEOUT="$CI_TIMEOUT"
TARGET_TEST=""

SAVE_LOG=false
RUN_DATETIME=""
OAUTH_ENABLED="${CI_TEST_OAUTH:-false}"

original_args=("$@")
while [[ $# -gt 0 ]]; do
    case "$1" in
        -b|--build)
            TARGET_COMPOSE_FILE="$COMPOSE_FILE"
            TARGET_TIMEOUT="$TIMEOUT"
            shift
            ;;
        --oauth)
            OAUTH_ENABLED=true
            shift
            ;;
        -t|--test)
            TARGET_TEST="$2"
            shift 2
            ;;
        -l|--log)
            SAVE_LOG=true
            # optional datetime, so a batch of runs can share one log folder
            if [[ -n "$2" && "$2" != -* ]]; then
                RUN_DATETIME="$2"
                shift
            fi
            shift
            ;;
        *)
            break
            ;;
    esac
done

case "${OAUTH_ENABLED,,}" in
    true|1) OAUTH_ENABLED=true ;;
    false|0) OAUTH_ENABLED=false ;;
    *) echo "Invalid CI_TEST_OAUTH: $OAUTH_ENABLED" >&2; exit 2 ;;
esac

# check if the test name is in the allowed test pool
if [[ ! "$TARGET_TEST" =~ ^($TEST_POOL)$ ]]; then
    echo "Error: test name '$TARGET_TEST' is not in the allowed test pool"
    echo "Allowed tests: $TEST_POOL"
    exit 1
fi

RUN_DATETIME="${RUN_DATETIME:-$(date +%Y%m%d-%H%M%S)}"
LOG_DIR="log/$RUN_DATETIME/e2e-basic/$TARGET_TEST/${CI_TEST_CHARGING_MODE:-suite}"

# save docker compose logs (all + per service) into $LOG_DIR when -l is given
save_logs() {
    [ "$SAVE_LOG" = true ] || return 0
    mkdir -p "$LOG_DIR"
    timeout -k 5s 30s docker compose -f "$TARGET_COMPOSE_FILE" logs --no-color -t > "$LOG_DIR/all.log" 2>&1
    for svc in $(timeout -k 5s 15s docker compose -f "$TARGET_COMPOSE_FILE" config --services); do
        timeout -k 5s 30s docker compose -f "$TARGET_COMPOSE_FILE" logs --no-color -t "$svc" > "$LOG_DIR/$svc.log" 2>&1
    done
    echo "Docker compose logs saved to $LOG_DIR"
}

if [[ -z "${CI_TEST_CHARGING_MODE:-}" ]]; then
    result=0
    CI_TEST_CHARGING_MODE=offline bash "$0" "${original_args[@]}" || result=1
    CI_TEST_CHARGING_MODE=online bash "$0" "${original_args[@]}" || result=1
    exit "$result"
fi
case "$CI_TEST_CHARGING_MODE" in
    offline|online) ;;
    *) echo "Invalid charging mode" >&2; exit 2 ;;
esac

# Compose uses fixed container names and, for some suites, fixed subnets.
# Serialize project operations on this Linux runner host.
exec 9>"/tmp/free5gc-ci-test-${UID}.lock" || exit 1
flock -w 1800 9 || { echo 'Cannot acquire ci-test Docker lock' >&2; exit 1; }

unset NRF_CONFIG_FILE FREE5GC_CERT_DIR NRF_PRIVATE_DIR
cert_dir=""
if [[ "$OAUTH_ENABLED" == true ]]; then
    PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)" || exit 1
    export NRF_CONFIG_FILE="$PROJECT_ROOT/config/nrfCfg.oauth.yaml"
    [[ -f "$NRF_CONFIG_FILE" ]] || { echo "Missing OAuth NRF config" >&2; exit 1; }
fi

cleanup() {
    local result=$?
    trap - EXIT
    if ! timeout -k 5s 2m docker compose -f "$TARGET_COMPOSE_FILE" down --remove-orphans -v; then
        echo "Compose teardown failed" >&2
        if [[ "$result" == 0 ]]; then result=1; fi
    fi
    if [[ -n "$cert_dir" ]]; then
        rm -rf -- "$cert_dir" || result=1
    fi
    exit "$result"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

if [[ "$OAUTH_ENABLED" == true ]]; then
    cert_dir="$(mktemp -d "${TMPDIR:-/tmp}/free5gc-oauth-certs.XXXXXXXX")" || exit 1
    export FREE5GC_CERT_DIR="$cert_dir/shared"
    export NRF_PRIVATE_DIR="$cert_dir/nrf"
    mkdir -m 700 -- "$FREE5GC_CERT_DIR" "$NRF_PRIVATE_DIR" || exit 1
    cp -R -- "$PROJECT_ROOT/cert/." "$FREE5GC_CERT_DIR/" || exit 1
    # NRF initializes fresh CA and signer keys in its separate mount, then
    # publishes their public certs into the shared mount before startup.
    rm -f -- "$FREE5GC_CERT_DIR"/{root,nrf}.{key,pem} || exit 1
    echo "OAuth ON: fresh NRF signing identity (HTTP test network)"
fi

# Require a clean project baseline before starting the next case.
timeout -k 5s 2m docker compose -f "$TARGET_COMPOSE_FILE" down --remove-orphans -v || exit 1

# Up the containers using the selected compose file
if ! docker compose -f "$TARGET_COMPOSE_FILE" up -d --wait --wait-timeout "$TARGET_TIMEOUT"; then
    echo "Error: Failed to start containers using $TARGET_COMPOSE_FILE"
    timeout -k 5s 30s docker compose -f "$TARGET_COMPOSE_FILE" logs
    save_logs
    exit 1
fi

sleep 5

# run test
echo "Running test... $TARGET_TEST"

case "$TARGET_TEST" in
    "TestRegPduCharging")
        timeout -k 5s 20m docker compose -f "$TARGET_COMPOSE_FILE" exec -T --interactive=false ue /bin/bash -c \
            'cd test && ./test-e2e-reg-pdu-charging.sh "$1"' bash "$CI_TEST_CHARGING_MODE"
        exit_code=$?
    ;;
esac

if [ $exit_code -ne 0 ]; then
    for svc in free5gc-upf ue; do
        echo "Network diagnostics for $svc"
        timeout -k 2s 10s docker compose -f "$TARGET_COMPOSE_FILE" exec -T --interactive=false "$svc" sh -c '
            ip -4 addr
            ip -4 route
            ip -4 route get 8.8.8.8
            ip -4 route get 1.1.1.1
            ip -s link
            cat /proc/sys/net/ipv4/ip_forward
            iptables -t nat -nvL POSTROUTING
            iptables -nvL FORWARD
            ip xfrm policy
        '
    done
    timeout -k 5s 30s docker compose -f "$TARGET_COMPOSE_FILE" logs
fi

save_logs

echo "Test completed with exit code: $exit_code"

exit $exit_code