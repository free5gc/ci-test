#!/bin/bash

##########################
#
# usage:
# ./ci-test-basic.sh <test-name>
#
# e.g. ./ci-test-basic.sh TestBasicCharging
#
##########################

TEST_POOL="TestBasicCharging"

# check if the test name is in the allowed test pool
if [[ ! "$1" =~ ^($TEST_POOL)$ ]]; then
    echo "Error: test name '$1' is not in the allowed test pool"
    echo "Allowed tests: $TEST_POOL"
    exit 1
fi

# run test
echo "Running test... $1"

case "$1" in
    "TestBasicCharging")
        docker exec ue /bin/bash -c "cd test && ./test-basic-charging.sh"
        exit_code=$?
    ;;
esac

echo "Test completed with exit code: $exit_code"
exit $exit_code