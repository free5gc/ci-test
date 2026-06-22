# ULCL Traffic Influence

## Test Command

```bash
./ci-test-ulcl-ti.sh TestULCLTrafficInfluence
```

## Test File

- [ulclTrafficInfluence_test.go](../test/goTest/ulclTrafficInfluence_test.go)

## Test Cases

1. Before Traffic Influence
   - Ping n6gw: expected ping success
   - Ping mec: expected ping failed
2. After Traffic Influence
   - Ping n6gw: expected ping failed
   - Ping mec: expected ping success
3. Reset Traffic Influence
   - Ping n6gw: expected ping success
   - Ping mec: expected ping failed
4. Flow Level Ping(used to check flow level charging record)
   - Ping 1.1.1.1: expected ping success
5. Check charging data record
   - Check session level charging record: expected charging record is not empty
   - Check flow level charging record: expected charging record is not empty

## Test Steps

1. Post ue subscription data to db via web console's api
2. Activate free-ue
3. Run [test cases](#test-cases)
4. Deactivate free-ue
5. Delete ue subscription data from db via web console's api
