#!/bin/bash

##########################
#
# usage:
# ./ci-test-e2e-basic.sh -t <test-name> <-b>
#
# e.g. ./ci-test-e2e-basic.sh -t TestRegPduCharging <-b>
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

# force-cleanup any leftovers from a previous run that failed to tear down cleanly
docker compose -f "$TARGET_COMPOSE_FILE" down --remove-orphans -v || true
docker rm -f mongodb ci-mongodb 2>/dev/null || true

# Up the containers using the selected compose file
if ! docker compose -f "$TARGET_COMPOSE_FILE" up -d --wait --wait-timeout "$TARGET_TIMEOUT"; then
    echo "Error: Failed to start containers using $TARGET_COMPOSE_FILE"
    exit 1
fi

sleep 5

# run test
echo "Running test... $TARGET_TEST"

case "$TARGET_TEST" in
    "TestRegPduCharging")
        docker exec ue /bin/bash -c "cd test && ./test-e2e-reg-pdu-charging.sh"
        exit_code=$?
    ;;
esac

if [ $exit_code -ne 0 ]; then
    docker compose -f "$TARGET_COMPOSE_FILE" logs
fi

# Cleanup: Stop and remove the containers after the test
if ! docker compose -f "$TARGET_COMPOSE_FILE" down --remove-orphans -v; then
    echo "Warning: Failed to stop and remove containers using $TARGET_COMPOSE_FILE, forcing cleanup"
    docker compose -f "$TARGET_COMPOSE_FILE" rm -f -s -v || true
fi

echo "Test completed with exit code: $exit_code"

exit $exit_code