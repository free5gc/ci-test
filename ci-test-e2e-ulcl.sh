#!/bin/bash

##########################
#
# usage:
# ./ci-test-ulcl-mp.sh -t <test-name> <-b> <-l [datetime]>
#
# e.g. ./ci-test-ulcl-mp.sh -t TestULCLTrafficInfluence <-b> <-l>
#
# -b, --build          : use the build compose file
# -l, --log [datetime] : save docker compose logs to log/<datetime>/e2e-ulcl/<test-name>/
#                        (datetime defaults to now, format YYYYMMDD-HHMMSS)
#
##########################

TEST_POOL="TestULCLTrafficInfluence|TestULCLMultiPathUe"

COMPOSE_FILE="composes/build/docker-compose-e2e-ulcl.yaml"
CI_COMPOSE_FILE="composes/docker-compose-ci-e2e-ulcl.yaml"

TIMEOUT=1800 # 30 minutes
CI_TIMEOUT=300 # 5 minutes

TARGET_COMPOSE_FILE="$CI_COMPOSE_FILE"
TARGET_TIMEOUT="$CI_TIMEOUT"
TARGET_TEST=""

SAVE_LOG=false
RUN_DATETIME=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        -b|--build)
            TARGET_COMPOSE_FILE="$COMPOSE_FILE"
            TARGET_TIMEOUT="$TIMEOUT"
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

# check if the test name is in the allowed test pool
if [[ ! "$TARGET_TEST" =~ ^($TEST_POOL)$ ]]; then
    echo "Error: test name '$TARGET_TEST' is not in the allowed test pool"
    echo "Allowed tests: $TEST_POOL"
    exit 1
fi

RUN_DATETIME="${RUN_DATETIME:-$(date +%Y%m%d-%H%M%S)}"
LOG_DIR="log/$RUN_DATETIME/e2e-ulcl/$TARGET_TEST"

# save docker compose logs (all + per service) into $LOG_DIR when -l is given
save_logs() {
    [ "$SAVE_LOG" = true ] || return 0
    mkdir -p "$LOG_DIR"
    docker compose -f "$TARGET_COMPOSE_FILE" logs --no-color -t > "$LOG_DIR/all.log" 2>&1
    for svc in $(docker compose -f "$TARGET_COMPOSE_FILE" config --services); do
        docker compose -f "$TARGET_COMPOSE_FILE" logs --no-color -t "$svc" > "$LOG_DIR/$svc.log" 2>&1
    done
    echo "Docker compose logs saved to $LOG_DIR"
}

# force-cleanup any leftovers from a previous run that failed to tear down cleanly
docker compose -f "$TARGET_COMPOSE_FILE" down --remove-orphans -v || true
docker rm -f mongodb ci-mongodb 2>/dev/null || true

# Up the containers using the selected compose file
if ! docker compose -f "$TARGET_COMPOSE_FILE" up -d --wait --wait-timeout "$TARGET_TIMEOUT"; then
    echo "Error: Failed to start containers using $TARGET_COMPOSE_FILE"
    docker compose -f "$TARGET_COMPOSE_FILE" logs
    save_logs
    docker compose -f "$TARGET_COMPOSE_FILE" down --remove-orphans -v || true
    exit 1
fi

sleep 5

# run test
echo "Running test... $TARGET_TEST"

case "$TARGET_TEST" in
    "TestULCLTrafficInfluence")
        docker exec ue-0 /bin/bash -c "cd test && ./test-e2e-ulcl-ti.sh"
        exit_code=$?
    ;;
    "TestULCLMultiPathUe")
        docker exec ue-1 /bin/bash -c "cd test && ./test-e2e-ulcl-mp.sh TestULCLMultiPathUe1"
        exit_code_1=$?
        docker exec ue-2 /bin/bash -c "cd test && ./test-e2e-ulcl-mp.sh TestULCLMultiPathUe2"
        exit_code_2=$?
        if [ $exit_code_1 -ne 0 ] || [ $exit_code_2 -ne 0 ]; then
            exit_code=1
        else
            exit_code=0
        fi
    ;;
esac

if [ $exit_code -ne 0 ]; then
    docker compose -f "$TARGET_COMPOSE_FILE" logs
fi

save_logs

# Cleanup: Stop and remove the containers after the test
if ! docker compose -f "$TARGET_COMPOSE_FILE" down --remove-orphans -v; then
    echo "Warning: Failed to stop and remove containers using $TARGET_COMPOSE_FILE, forcing cleanup"
    docker compose -f "$TARGET_COMPOSE_FILE" rm -f -s -v || true
fi

echo "Test completed with exit code: $exit_code"

exit $exit_code
