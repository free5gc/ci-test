#!/bin/bash

##########################
#
# usage:
# ./test-it-serviceproxy.sh
#
# e.g. ./test-it-serviceproxy.sh
#
# note: AUSF must be advertised through SCP (../script/scp.sh -e) before the
#       compose is up; ci-test-it.sh does this automatically for
#       TestServiceProxy and runs ../script/scp.sh -d afterwards
#
##########################

echo "Running IT service proxy test"

# post ue data to db
./api-webconsole-subscribtion-data-action.sh post json/webconsole-subscription-data-it.json
if [ $? -ne 0 ]; then
    echo "Failed to post subscription data"
    exit 1
fi

cd goTest
go test -v -vet=off -run TestServiceProxy
go_test_exit_code=$?
cd ..

# delete ue data from db
./api-webconsole-subscribtion-data-action.sh delete json/webconsole-subscription-data-it.json
if [ $? -ne 0 ]; then
    echo "Failed to delete subscription data"
    exit 1
fi

# return the test exit code
exit $go_test_exit_code
