#!/bin/bash

##########################
#
# usage:
# ./ci-test-ulcl-mp.sh -t <test-name> <-b>
#
# e.g. ./ci-test-ulcl-mp.sh -t TestULCLTrafficInfluence <-b>
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

# remove any existing containers
docker rm -f mongodb ci-mongodb || true

# Up the containers using the selected compose file
if ! docker compose -f "$TARGET_COMPOSE_FILE" up -d --wait --wait-timeout "$TARGET_TIMEOUT"; then
    echo "Error: Failed to start containers using $TARGET_COMPOSE_FILE"
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

# Cleanup: Stop and remove the containers after the test
if ! docker compose -f "$TARGET_COMPOSE_FILE" down; then
    echo "Warning: Failed to stop and remove containers using $TARGET_COMPOSE_FILE"
fi

echo "Test completed with exit code: $exit_code"
exit $exit_code
