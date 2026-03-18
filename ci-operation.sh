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
    echo "  - up <basic-charging | ulcl-ti | ulcl-mp>: bring up the compose in detached mode and wait for readiness"
    echo "  - down <basic-charging | ulcl-ti | ulcl-mp>: shut down the compose and remove orphans"
    echo "  - test <basic-charging | ulcl-ti | ulcl-mp>: run ULCL test"
    echo "  - exec <ue | ue-1 | ue-2>: enter the ue container"
}

required_images_for_target() {
    echo "free5gc/base:latest"
    echo "free5gc/upf-base:latest"
    echo "free5gc/nrf-base:latest"
    echo "free5gc/amf-base:latest"
    echo "free5gc/ausf-base:latest"
    echo "free5gc/nssf-base:latest"
    echo "free5gc/pcf-base:latest"
    echo "free5gc/smf-base:latest"
    echo "free5gc/udm-base:latest"
    echo "free5gc/udr-base:latest"
    echo "free5gc/chf-base:latest"
    echo "free5gc/nef-base:latest"
    echo "free5gc/webconsole-base:latest"
}

check_required_images() {
    local target="$1"
    local missing_images=()
    local image

    while IFS= read -r image; do
        if ! docker image inspect "$image" >/dev/null 2>&1; then
            missing_images+=("$image")
        fi
    done < <(required_images_for_target "$target")

    if [ ${#missing_images[@]} -gt 0 ]; then
        echo "Error: required local images are missing for scenario '$target':"
        for image in "${missing_images[@]}"; do
            echo "  - $image"
        done
        echo ""
        echo "Please build images first:"
        echo "  sudo ./ci-operation.sh build"
        return 1
    fi

    return 0
}

compose_file_for_target() {
    case "$1" in
        "basic-charging")
            echo "docker-compose-basic.yaml"
        ;;
        "ulcl-ti")
            echo "docker-compose-ulcl-ti.yaml"
        ;;
        "ulcl-mp")
            echo "docker-compose-ulcl-mp.yaml"
        ;;
        *)
            return 1
    esac
}

cleanup_other_scenarios() {
    local target="$1"
    local scenario
    local compose_file

    for scenario in basic-charging ulcl-ti ulcl-mp; do
        if [ "$scenario" = "$target" ]; then
            continue
        fi

        compose_file=$(compose_file_for_target "$scenario") || continue
        docker compose -f "$compose_file" down --remove-orphans >/dev/null 2>&1 || true
    done
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
            compose_file=$(compose_file_for_target "$2") || { usage; exit 1; }
            check_required_images "$2" || exit 1
            cleanup_other_scenarios "$2"

            docker compose -f "$compose_file" up -d --wait --wait-timeout "${COMPOSE_WAIT_TIMEOUT:-300}"
        ;;
        "down")
            compose_file=$(compose_file_for_target "$2") || { usage; exit 1; }
            docker compose -f "$compose_file" down --remove-orphans
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
