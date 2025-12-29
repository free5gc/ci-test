package test

import (
	packetRusher "test/packetRusher"
	pinger "test/pinger"
	"testing"
	"time"
)

var testBasicChargingCases = []struct {
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

func TestBasicCharging(t *testing.T) {
	pr := packetRusher.NewPacketRusher()
	pr.Activate()
	defer pr.Deactivate()

	time.Sleep(5 * time.Second)

	for _, testCase := range testBasicChargingCases {
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
