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
    echo "  - up <basic-charging | ulcl-ti | ulcl-mp>: bring up the compose"
    echo "  - down <basic-charging | ulcl-ti | ulcl-mp>: shut down the compose"
    echo "  - test <basic-charging | ulcl-ti | ulcl-mp>: run ULCL test"
    echo "  - exec <ue | ue-1 | ue-2>: enter the ue container"
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
            make nfs
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
                    docker exec ue /bin/bash -c "cd /root/test && ./test-basic-charging.sh"
                ;;
                "ulcl-ti")
                    docker exec ue /bin/bash -c "cd /root/test && ./test-ulcl-ti.sh TestULCLTrafficInfluence"
                ;;
                "ulcl-mp")
                    docker exec ue-1 /bin/bash -c "cd /root/test && ./test-ulcl-mp.sh TestULCLMultiPathUe1"
                    docker exec ue-2 /bin/bash -c "cd /root/test && ./test-ulcl-mp.sh TestULCLMultiPathUe2"
                ;;
                *)
                    usage
            esac
        ;;
        "exec")
            case "$2" in
                "ue")
                    docker exec -it ue bash
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
