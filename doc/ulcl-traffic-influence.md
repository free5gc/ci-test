# ULCL Traffic Influence

## Topology

```text
ci0(ue0) - gnb0 - i-upf0 - psa-upf0 - N6GW / Internet
                   |
                  MEC
```

## Test Command

```bash
./ci-test-e2e-ulcl.sh --build --test TestULCLTrafficInfluence
```

## Test File

- [e2e_ulclTrafficInfluence_test.go](../test/goTest/e2e_ulclTrafficInfluence_test.go)
- [test-e2e-ulcl-ti.sh](../test/test-e2e-ulcl-ti.sh)

## Test Cases

The shell script runs the original offline/online cases, followed by full, partial and mixed overlap with offline/online subscriptions: eight sessions in total.

### Original TI

1. Before Traffic Influence
   - Ping n6gw: expected ping success
   - Ping mec: expected ping failed
2. After Traffic Influence
   - Ping n6gw: expected ping failed
   - Ping mec: expected ping success
3. Reset Traffic Influence
   - Ping n6gw: expected ping success
   - Ping mec: expected ping failed
4. Flow Level Ping (used to check flow level charging record)
   - Ping 1.1.1.1: expected ping success
5. Check charging data record
   - Check session level charging record: expected charging record is not empty
   - Check flow level charging record: expected charging record is not empty

### Flow rule overlap

| Go test | Service filter | TI remote filter | N6GW during TI | MEC during TI |
| --- | --- | --- | --- | --- |
| `TestTrafficInfluenceFlowRuleOverlapFull` | `10.100.100.0/24` | `10.100.100.0/24` | success | success |
| `TestTrafficInfluenceFlowRuleOverlapPartial` | `10.100.0.0/16` | `10.100.100.0/24` | success | success |
| `TestTrafficInfluenceFlowRuleOverlapMixed` | `10.100.100.0/24` | `10.100.0.0/16` | failed | success |

1. Before Traffic Influence
   - Ping n6gw and 1.1.1.1: expected ping success
   - Ping mec: expected ping failed
2. After Traffic Influence
   - Ping n6gw and mec: expected results shown in the table
   - Ping 1.1.1.1: expected ping success
3. Reset Traffic Influence
   - Ping n6gw: expected ping success
   - Ping mec: expected ping failed
4. Flow Level Ping
   - Ping 1.1.1.1: expected ping success

The mixed TI filter includes N6GW and directs its packets toward the MEC exit, where N6GW is unreachable in this lab topology. The full/partial TI filters exclude N6GW. All filters exclude 1.1.1.1.

Full and partial share [ti-data-mec.json](../test/json/ti-data-mec.json); their service filters differ. Mixed reuses [ti-data.json](../test/json/ti-data.json). Subscription files are `webconsole-subscription-data-ti-<case>-<charging>.json`.

`tiOperation(t, "put")` keeps the original payload. An optional path relative to `test/`, such as `tiOperation(t, "put", "json/ti-data-mec.json")`, selects a different payload through the same API helper script ([api-nef-ti-data-action.sh](../test/api-nef-ti-data-action.sh)), which provisions TI through NEF's `3gpp-traffic-influence` API as an AF (with an OAuth token when NRF oauth is enabled).

Overlap cases check connectivity only; charging record assertions remain in the original TI test. Ping success does not verify QFI/QER contents, rate enforcement or final charging settlement. See the [default-route known issue](known-issue-ulcl-default-route.md) if Internet probes fail while local probes succeed.

## Test Steps

1. Post ue subscription data to db via web console's api
2. Activate free-ue
3. Run [test cases](#test-cases)
4. Deactivate free-ue
5. Delete ue subscription data from db via web console's api
