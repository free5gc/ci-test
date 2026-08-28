# Reg Pdu Charging

## Topology

```test
ci - gnb - upf
```

## Test Command

```bash
./ci-test-basic.sh TestRegPduCharging
```

## Test File

- [e2e_regPduCharging_test.go](../test/goTest//e2e_regPduCharging_test.go)

## Test Cases

1. UE Registration
2. Ping
3. Check charging data record
   - Check session level charging record: expected charging record is not empty
   - Check flow level charging record: expected charging record is not empty

## Test Steps

1. Post ue subscription data to db via web console's api
2. Activate free-ue
3. Run [test cases](#test-cases)
4. Deactivate free-ue
5. Delete ue subscription data from db via web console's api
