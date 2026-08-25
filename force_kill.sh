#!/bin/bash

docker ps -aq | xargs -r docker rm -f
docker network prune -f
docker volume prune -f
