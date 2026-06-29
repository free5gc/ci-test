#! /bin/bash

##########################
#
# This script is used for quickly testing the function
#
##########################
#
# usage:
# ./ ci-operation.sh [action] [target]
#
# e.g. ./ci-operation.sh test ulcl-ti
#
##########################

usage() {
    echo "usage: ./ci-operation.sh [action] [target]"
    echo "  - pull: remove the existed free5gc repo and clone a new free5gc with its NFs"
    echo "  - fetch [NF] [PR#]: fetch the target NF's PR"
    echo "  - testAll: run all free5gc tests"
    echo "  - build: build the necessary images"
    echo "  - up <basic-charging | ulcl-ti | ulcl-mp>: bring up the compose"
    echo "  - down <basic-charging | ulcl-ti | ulcl-mp>: shut down the compose"
    echo "  - test <basic-charging | ulcl-ti | ulcl-mp>: run ULCL test"
    echo "  - exec <ue | ue-1 | ue-2>: enter the ue container"
}

COMPOSE_DIR="composes/build"

IT_COMPOSE_FILE="$COMPOSE_DIR/docker-compose-it.yaml"
E2E_BASIC_COMPOSE_FILE="$COMPOSE_DIR/docker-compose-e2e-basic.yaml"
E2E_ULCL_COMPOSE_FILE="$COMPOSE_DIR/docker-compose-e2e-ulcl.yaml"

main() {
    if [ $# -ne 1 ] && [ $# -ne 2 ] && [ $# -ne 3 ]; then
        usage
    fi

    case "$1" in
        "pull")
            rm -rf free5gc
            git clone -j `nproc` --recursive https://github.com/free5gc/free5gc
        ;;
        "fetch")
            cd free5gc/NFs/$2
            git fetch origin pull/$3/head:pr-$3
            git checkout pr-$3
            cd ../../../
        ;;
        "testAll")
            cd free5gc/
            make all
            ./force_kill.sh
            ./test.sh All
            cd ../
        ;;
        "build")
            make nfs
        ;;
        "up")
            case "$2" in
                "it")
                    docker compose -f $IT_COMPOSE_FILE up --build
                ;;
                "basic")
                    docker compose -f $E2E_BASIC_COMPOSE_FILE up --build
                ;;
                "ulcl")
                    docker compose -f $E2E_ULCL_COMPOSE_FILE up --build
                ;;
                *)
                    usage
            esac
        ;;
        "down")
            case "$2" in
                "it")
                    docker compose -f $IT_COMPOSE_FILE down
                ;;
                "basic")
                    docker compose -f $E2E_BASIC_COMPOSE_FILE down
                ;;
                "ulcl")
                    docker compose -f $E2E_ULCL_COMPOSE_FILE down
                ;;
                *)
                    usage
            esac
        ;;
        "test")
            case "$2" in
                "it")
                    ./ci-test-it.sh --test TestRegistration --build
                ;;
                "basic")
                    ./ci-test-e2e-basic.sh --test TestRegPduCharging --build
                ;;
                "ulcl")
                    ./ci-test-e2e-ulcl.sh --test TestULCLTrafficInfluence --build
                    ./ci-test-e2e-ulcl.sh --test TestULCLMultiPathUe --build
                ;;
                *)
                    usage
            esac
        ;;
        "exec")
            case "$2" in
                "it")
                    docker exec -it it bash
                ;;
                "ue-0")
                    docker exec -it ue-0 bash
                ;;
                "ue-1")
                    docker exec -it ue-1 bash
                ;;
                "ue-2")
                    docker exec -it ue-2 bash
                ;;
                *)
                    usage
            esac
        ;;
    esac
}

main "$@"