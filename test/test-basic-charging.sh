#!/bin/bash

##########################
#
# usage:
# ./test-basic-charging.sh
#
# e.g. ./test-basic-charging.sh
#
##########################

echo "test basic offline charging"

# post ue (ci-test PacketRusher) data to db
./api-webconsole-subscribtion-data-action.sh post json/webconsole-subscription-data-basic-charging-offline.json
if [ $? -ne 0 ]; then
    echo "Failed to post subscription data"
    exit 1
fi

# run test
cd goTest
go test -v -vet=off -run TestBasicCharging
go_test_exit_code=$?
cd ..

# delete ue (ci-test PacketRusher) data from db
./api-webconsole-subscribtion-data-action.sh delete json/webconsole-subscription-data-basic-charging-offline.json
if [ $? -ne 0 ]; then
    echo "Failed to delete subscription data"
    exit 1
fi

echo "test basic online charging"

# post ue (ci-test PacketRusher) data to db
./api-webconsole-subscribtion-data-action.sh post json/webconsole-subscription-data-basic-charging-online.json
if [ $? -ne 0 ]; then
    echo "Failed to post subscription data"
    exit 1
fi

# run test
cd goTest
go test -v -vet=off -run TestBasicCharging
go_test_exit_code=$?
cd ..

# delete ue (ci-test PacketRusher) data from db
./api-webconsole-subscribtion-data-action.sh delete json/webconsole-subscription-data-basic-charging-online.json
if [ $? -ne 0 ]; then
    echo "Failed to delete subscription data"
    exit 1
fi

# return the test exit code
exit $go_test_exit_code