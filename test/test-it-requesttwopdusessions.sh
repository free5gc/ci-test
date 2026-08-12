#!/bin/bash

##########################
#
# usage:
# ./test-it-requesttwopdusessions.sh
#
# e.g. ./test-it-requesttwopdusessions.sh
#
##########################

echo "Running IT Request Two PDU Sessions test"

# post ue data to db
./api-webconsole-subscribtion-data-action.sh post json/webconsole-subscription-data-it.json
if [ $? -ne 0 ]; then
    echo "Failed to post subscription data"
    exit 1
fi

cd goTest
go test -v -vet=off -run TestRequestTwoPDUSessions
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
