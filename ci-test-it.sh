#!/bin/bash

##########################
#
# usage:
# ./ci-test-it.sh -t <test-name> <-b> <-l [datetime]>
#
# e.g. ./ci-test-it.sh -t TestRegistration <-b> <-l>
#
# -b, --build          : use the build compose file
# -l, --log [datetime] : save docker compose logs to log/<datetime>/it/<test-name>/
#                        (datetime defaults to now, format YYYYMMDD-HHMMSS)
#
##########################

TEST_POOL="TestRegistration|TestDeregistration|TestGUTIRegistration|TestEAPAKAPrimeAuthentication|TestDuplicateRegistration|TestServiceRequest|TestPDUSessionReleaseRequest|TestNasReroute|TestN2Handover|TestXnHandover|TestPaging|TestReSynchronization|TestMultiAmfRegistration|TestDC|TestDynamicDC|TestXnDcHandover|TestRequestTwoPDUSessions|TestN3iwf|TestTngf"

COMPOSE_FILE="composes/build/docker-compose-it.yaml"
CI_COMPOSE_FILE="composes/docker-compose-ci-it.yaml"

TIMEOUT=1800 # 30 minutes
CI_TIMEOUT=300 # 5 minutes

TARGET_COMPOSE_FILE="$CI_COMPOSE_FILE"
TARGET_TIMEOUT="$CI_TIMEOUT"
TARGET_TEST=""

SAVE_LOG=false
RUN_DATETIME=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        -b|--build)
            TARGET_COMPOSE_FILE="$COMPOSE_FILE"
            TARGET_TIMEOUT="$TIMEOUT"
            shift
            ;;
        -t|--test)
            TARGET_TEST="$2"
            shift 2
            ;;
        -l|--log)
            SAVE_LOG=true
            # optional datetime, so a batch of runs can share one log folder
            if [[ -n "$2" && "$2" != -* ]]; then
                RUN_DATETIME="$2"
                shift
            fi
            shift
            ;;
        *)
            break
            ;;
    esac
done

# check if the test name is in the allowed test pool
if [[ ! "$TARGET_TEST" =~ ^($TEST_POOL)$ ]]; then
    echo "Error: test name '$TARGET_TEST' is not in the allowed test pool"
    echo "Allowed tests: $TEST_POOL"
    exit 1
fi

RUN_DATETIME="${RUN_DATETIME:-$(date +%Y%m%d-%H%M%S)}"
LOG_DIR="log/$RUN_DATETIME/it/$TARGET_TEST"

# save docker compose logs (all + per service) into $LOG_DIR when -l is given
save_logs() {
    [ "$SAVE_LOG" = true ] || return 0
    mkdir -p "$LOG_DIR"
    docker compose -f "$TARGET_COMPOSE_FILE" logs --no-color -t > "$LOG_DIR/all.log" 2>&1
    for svc in $(docker compose -f "$TARGET_COMPOSE_FILE" config --services); do
        docker compose -f "$TARGET_COMPOSE_FILE" logs --no-color -t "$svc" > "$LOG_DIR/$svc.log" 2>&1
    done
    echo "Docker compose logs saved to $LOG_DIR"
}

# force-cleanup any leftovers from a previous run that failed to tear down cleanly
docker compose -f "$TARGET_COMPOSE_FILE" down --remove-orphans -v || true
docker rm -f mongodb ci-mongodb 2>/dev/null || true

# Up the containers using the selected compose file
if ! docker compose -f "$TARGET_COMPOSE_FILE" up -d --wait --wait-timeout "$TARGET_TIMEOUT"; then
    echo "Error: Failed to start containers using $TARGET_COMPOSE_FILE"
    docker compose -f "$TARGET_COMPOSE_FILE" logs
    save_logs
    docker compose -f "$TARGET_COMPOSE_FILE" down --remove-orphans -v || true
    exit 1
fi

sleep 5

# run test
echo "Running test... $TARGET_TEST"

case "$TARGET_TEST" in
    "TestRegistration")
        docker exec it /bin/bash -c "cd /root/test && ./test-it-registration.sh"
        exit_code=$?
    ;;
    "TestDeregistration")
        docker exec it /bin/bash -c "cd /root/test && ./test-it-deregistration.sh"
        exit_code=$?
    ;;
    "TestGUTIRegistration")
        docker exec it /bin/bash -c "cd /root/test && ./test-it-gutiregistration.sh"
        exit_code=$?
    ;;
    "TestEAPAKAPrimeAuthentication")
        docker exec it /bin/bash -c "cd /root/test && ./test-it-eapakaprime.sh"
        exit_code=$?
    ;;
    "TestDuplicateRegistration")
        docker exec it /bin/bash -c "cd /root/test && ./test-it-duplicateregistration.sh"
        exit_code=$?
    ;;
    "TestServiceRequest")
        docker exec it /bin/bash -c "cd /root/test && ./test-it-servicerequest.sh"
        exit_code=$?
    ;;
    "TestPDUSessionReleaseRequest")
        docker exec it /bin/bash -c "cd /root/test && ./test-it-pdusessionreleaserequest.sh"
        exit_code=$?
    ;;
    "TestNasReroute")
        docker exec it /bin/bash -c "cd /root/test && ./test-it-nasreroute.sh"
        exit_code=$?
    ;;
    "TestN2Handover")
        docker exec it /bin/bash -c "cd /root/test && ./test-it-n2handover.sh"
        exit_code=$?
    ;;
    "TestXnHandover")
        docker exec it /bin/bash -c "cd /root/test && ./test-it-xnhandover.sh"
        exit_code=$?
    ;;
    "TestPaging")
        docker exec it /bin/bash -c "cd /root/test && ./test-it-paging.sh"
        exit_code=$?
    ;;
    "TestReSynchronization")
        docker exec it /bin/bash -c "cd /root/test && ./test-it-resynchronization.sh"
        exit_code=$?
    ;;
    "TestMultiAmfRegistration")
        docker exec it /bin/bash -c "cd /root/test && ./test-it-multiamfregistration.sh"
        exit_code=$?
    ;;
    "TestDC")
        docker exec it /bin/bash -c "cd /root/test && ./test-it-dc.sh"
        exit_code=$?
    ;;
    "TestDynamicDC")
        docker exec it /bin/bash -c "cd /root/test && ./test-it-dynamicdc.sh"
        exit_code=$?
    ;;
    "TestXnDcHandover")
        docker exec it /bin/bash -c "cd /root/test && ./test-it-xndchandover.sh"
        exit_code=$?
    ;;
    "TestRequestTwoPDUSessions")
        docker exec it /bin/bash -c "cd /root/test && ./test-it-requesttwopdusessions.sh"
        exit_code=$?
    ;;
    "TestN3iwf")
        docker exec it /bin/bash -c "cd /root/test && ./test-it-n3iwf.sh"
        exit_code=$?
    ;;
    "TestTngf")
        docker exec it /bin/bash -c "cd /root/test && ./test-it-tngf.sh"
        exit_code=$?
    ;;
esac

if [ $exit_code -ne 0 ]; then
    docker compose -f "$TARGET_COMPOSE_FILE" logs
fi

save_logs

# Cleanup: Stop and remove the containers after the test
if ! docker compose -f "$TARGET_COMPOSE_FILE" down --remove-orphans -v; then
    echo "Warning: Failed to stop and remove containers using $TARGET_COMPOSE_FILE, forcing cleanup"
    docker compose -f "$TARGET_COMPOSE_FILE" rm -f -s -v || true
fi

echo "Test completed with exit code: $exit_code"

exit $exit_code