# ULCL Multi-path

## Topology

```text
ci1(ue1) - gnb1 - i-upf1 - psa-upf1
ci2(ue2) - gnb2 - i-upf2 - psa-upf2
```

## Test Command

```bash
./ci-test-ulcl-mp.sh <TestULCLMultiPathCi1 | TestULCLMultiPathCi2>
```

## Test File

- [e2e_ulclMultiPath_test.go](../test/goTest/e2e_ulclMultiPath_test.go)

## Test Cases

1. Ping 1.1.1.1
2. Ping MEC(10.100.100.10)

## Test Steps

1. Post ue subscription data to db via web console's api
2. Activate free-ue
3. Run [test cases](#test-cases)
4. Deactivate free-ue
5. Delete ue subscription data from db via web console's api
