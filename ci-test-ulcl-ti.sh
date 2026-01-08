#!/bin/bash

##########################
#
# usage:
# ./ci-test-ulcl-ti.sh <test-name>
#
# e.g. ./ci-test-ulcl-ti.sh TestULCLTrafficInfluence
#
##########################

TEST_POOL="TestULCLTrafficInfluence"

# check if the test name is in the allowed test pool
if [[ ! "$1" =~ ^($TEST_POOL)$ ]]; then
    echo "Error: test name '$1' is not in the allowed test pool"
    echo "Allowed tests: $TEST_POOL"
    exit 1
fi

# run test
echo "Running test... $1"

docker exec ue /bin/bash -c "cd test && ./test-ulcl-ti.sh $1"
exit_code=$?

echo "Test completed with exit code: $exit_code"
exit $exit_code