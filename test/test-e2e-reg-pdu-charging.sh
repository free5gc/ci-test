#!/bin/bash

##########################
#
# usage:
# ./test-reg-pdu-charging.sh
#
# e.g. ./test-e2e-reg-pdu-charging.sh
#
##########################

echo "test reg pdu offline charging"

# post ue (ci-test free-ran-ue) data to db
./api-webconsole-subscribtion-data-action.sh post json/webconsole-subscription-data-reg-pdu-charging-offline.json
if [ $? -ne 0 ]; then
    echo "Failed to post subscription data"
    exit 1
fi

# run test
cd goTest
go test -v -vet=off -run TestRegPduCharging
go_test_exit_code=$?
cd ..

# delete ue (ci-test free-ran-ue) data from db
./api-webconsole-subscribtion-data-action.sh delete json/webconsole-subscription-data-reg-pdu-charging-offline.json
if [ $? -ne 0 ]; then
    echo "Failed to delete subscription data"
    exit 1
fi

echo "test reg pdu online charging"

# post ue (ci-test free-ran-ue) data to db
./api-webconsole-subscribtion-data-action.sh post json/webconsole-subscription-data-reg-pdu-charging-online.json
if [ $? -ne 0 ]; then
    echo "Failed to post subscription data"
    exit 1
fi

# run test
cd goTest
go test -v -vet=off -run TestRegPduCharging
go_test_exit_code=$?
cd ..

# delete ue (ci-test free-ran-ue) data from db
./api-webconsole-subscribtion-data-action.sh delete json/webconsole-subscription-data-reg-pdu-charging-online.json
if [ $? -ne 0 ]; then
    echo "Failed to delete subscription data"
    exit 1
fi

# return the test exit code
exit $go_test_exit_code