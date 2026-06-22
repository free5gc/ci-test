# ci-test

## Functional IT

## E2E

### Basic

- [BasicCharging](./doc/basicCharging.md)

### ULCL

- [Traffic Influence](./doc/ulcl-traffic-influence.md)
- [Multi-path](./doc/ulcl-multi-path.md)

## Test Workflow

1. Call `ci-test-xxx.sh` at root path.
2. The test directory will be mounted to the test container. The script called at first step will execute the test case in the container.
