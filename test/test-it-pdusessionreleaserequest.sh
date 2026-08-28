#!/bin/bash

##########################
#
# usage:
# ./test-it-pdusessionreleaserequest.sh
#
# e.g. ./test-it-pdusessionreleaserequest.sh
#
##########################

echo "Running IT PDU Session Release Request test"

# post ue data to db
./api-webconsole-subscribtion-data-action.sh post json/webconsole-subscription-data-it.json
if [ $? -ne 0 ]; then
    echo "Failed to post subscription data"
    exit 1
fi

cd goTest
go test -v -vet=off -run TestPDUSessionReleaseRequest
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
