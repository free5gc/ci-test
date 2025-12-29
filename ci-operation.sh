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
    echo "  - pull: remove the existed free5gc repo under base/ and clone a new free5gc with its NFs"
    echo "  - fetch [NF] [PR#]: fetch the target NF's PR"
    echo "  - testAll: run all free5gc tests"
    echo "  - build: build the necessary images"
    echo "  - up <ulcl-ti | ulcl-mp>: bring up the compose"
    echo "  - down <ulcl-ti | ulcl-mp>: shut down the compose"
    echo "  - test <ulcl-ti | ulcl-mp>: run ULCL test"
    echo "  - exec <ci | ci-1 | ci-2>: enter the ci container"
}

main() {
    if [ $# -ne 1 ] && [ $# -ne 2 ] && [ $# -ne 3 ]; then
        usage
    fi

    case "$1" in
        "pull")
            cd base
            rm -rf free5gc
            git clone -j `nproc` --recursive https://github.com/free5gc/free5gc
            cd ..
        ;;
        "fetch")
            cd base/free5gc/NFs/$2
            git fetch origin pull/$3/head:pr-$3
            git checkout pr-$3
            cd ../../../../
        ;;
        "testAll")
            cd base/free5gc/
            make all
            ./force_kill.sh
            ./test.sh All
            cd ../../
        ;;
        "build")
            make ulcl
        ;;
        "up")
            case "$2" in
                "basic-charging")
                    docker compose -f docker-compose-basic.yaml up
                ;;
                "ulcl-ti")
                    docker compose -f docker-compose-ulcl-ti.yaml up
                ;;
                "ulcl-mp")
                    docker compose -f docker-compose-ulcl-mp.yaml up
                ;;
                *)
                    usage
            esac
        ;;
        "down")
            case "$2" in
                "basic-charging")
                    docker compose -f docker-compose-basic.yaml down
                ;;
                "ulcl-ti")
                    docker compose -f docker-compose-ulcl-ti.yaml down
                ;;
                "ulcl-mp")
                    docker compose -f docker-compose-ulcl-mp.yaml down
                ;;
                *)
                    usage
            esac
        ;;
        "test")
            case "$2" in
                "basic-charging")
                    docker exec ci /bin/bash -c "cd /root/test && ./test-basic-charging.sh"
                ;;
                "ulcl-ti")
                    docker exec ci /bin/bash -c "cd /root/test && ./test-ulcl-ti.sh TestULCLTrafficInfluence"
                ;;
                "ulcl-mp")
                    docker exec ci-1 /bin/bash -c "cd /root/test && ./test-ulcl-mp.sh TestULCLMultiPathCi1"
                    docker exec ci-2 /bin/bash -c "cd /root/test && ./test-ulcl-mp.sh TestULCLMultiPathCi2"
                ;;
                *)
                    usage
            esac
        ;;
        "exec")
            case "$2" in
                "ci")
                    docker exec -it ci bash
                ;;
                "ci-1")
                    docker exec -it ci-1 bash
                ;;
                "ci-2")
                    docker exec -it ci-2 bash
                ;;
                *)
                    usage
            esac
        ;;
    esac
}

main "$@"
