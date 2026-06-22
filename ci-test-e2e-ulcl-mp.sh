#!/bin/bash

##########################
#
# usage:
# ./ci-test-ulcl-mp.sh <test-name>
#
# e.g. ./ci-test-ulcl-mp.sh <TestULCLMultiPathUe1 | TestULCLMultiPathUe2>
#
##########################

TEST_POOL="TestULCLMultiPathUe1|TestULCLMultiPathUe2"

# check if the test name is in the allowed test pool
if [[ ! "$1" =~ ^($TEST_POOL)$ ]]; then
    echo "Error: test name '$1' is not in the allowed test pool"
    echo "Allowed tests: $TEST_POOL"
    exit 1
fi

# run test
echo "Running test... $1"

case "$1" in
    "TestULCLMultiPathUe1")
        docker exec ue-1 /bin/bash -c "cd test && ./test-ulcl-mp.sh $1"
        exit_code=$?
    ;;
    "TestULCLMultiPathUe2")
        docker exec ue-2 /bin/bash -c "cd test && ./test-ulcl-mp.sh $1"
        exit_code=$?
    ;;
esac

echo "Test completed with exit code: $exit_code"
exit $exit_code
