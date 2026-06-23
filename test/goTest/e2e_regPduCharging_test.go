package test

import (
	"test/freeRanUe"
	"test/pinger"
	"testing"
)

var testRegPduChargingCases = []struct {
	name        string
	destination string
}{
	{
		name:        "session level ping 8.8.8.8",
		destination: EIGHT_IP,
	},
	{
		name:        "flow level ping 1.1.1.1",
		destination: ONE_IP,
	},
}

func TestRegPduCharging(t *testing.T) {
	fru, err := freeRanUe.NewFreeRanUe()
	if err != nil {
		t.Fatalf("Failed to create FreeRanUe: %v", err)
	}
	err = fru.Activate()
	if err != nil {
		t.Fatalf("Failed to activate FreeRanUe: %v", err)
	}
	defer func() {
		if err := fru.Deactivate(); err != nil {
			t.Errorf("Failed to deactivate FreeRanUe: %v", err)
		}
	}()

	for _, testCase := range testRegPduChargingCases {
		t.Run(testCase.name, func(t *testing.T) {
			if err := pinger.Pinger(testCase.destination, NIC_1); err != nil {
				t.Errorf("Ping %s failed: expected ping success, but got %v", testCase.destination, err)
			}
			if err := pinger.Pinger(testCase.destination, NIC_1); err != nil {
				t.Errorf("Ping %s failed: expected ping success, but got %v", testCase.destination, err)
			}
		})
	}

	t.Run("Check Charging Record", func(t *testing.T) {
		checkChargingRecord(t)
	})
}
