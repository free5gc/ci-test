#!/bin/bash

# post ue (ci-test PacketRusher) data to db
./api-webconsole-subscribtion-data-action.sh post

# run test
cd goTest
go test -v -vet=off -run $1
cd ..

# delete ue (ci-test PacketRusher) data from db
./api-webconsole-subscribtion-data-action.sh delete