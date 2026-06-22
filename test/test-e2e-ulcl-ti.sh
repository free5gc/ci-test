#!/bin/bash

##########################
#
# usage:
# ./test-ulcl-ti.sh <test-name>
#
# e.g. ./test-ulcl-ti.sh TestULCLTrafficInfluence
#
##########################

echo "test TestULCLTrafficInfluence with offline charging"

# post ue (ci-test PacketRusher) data to db
./api-webconsole-subscribtion-data-action.sh post json/webconsole-subscription-data-ti-offline.json
if [ $? -ne 0 ]; then
    echo "Failed to post subscription data"
    exit 1
fi

# run test
cd goTest
go test -v -vet=off -run $1
go_test_exit_code=$?
cd ..

# delete ue (ci-test PacketRusher) data from db
./api-webconsole-subscribtion-data-action.sh delete json/webconsole-subscription-data-ti-offline.json
if [ $? -ne 0 ]; then
    echo "Failed to delete subscription data"
    exit 1
fi

echo "test TestULCLTrafficInfluence with online charging"

# post ue (ci-test PacketRusher) data to db
./api-webconsole-subscribtion-data-action.sh post json/webconsole-subscription-data-ti-online.json
if [ $? -ne 0 ]; then
    echo "Failed to post subscription data"
    exit 1
fi

# run test
cd goTest
go test -v -vet=off -run $1
go_test_exit_code=$?
cd ..

# delete ue (ci-test PacketRusher) data from db
./api-webconsole-subscribtion-data-action.sh delete json/webconsole-subscription-data-ti-online.json
if [ $? -ne 0 ]; then
    echo "Failed to delete subscription data"
    exit 1
fi

# return the test exit code
exit $go_test_exit_code
