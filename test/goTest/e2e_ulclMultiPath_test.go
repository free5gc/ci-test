package test

import (
	freeRanUE "test/freeRanUE"
	pinger "test/pinger"
	"testing"
	"time"
)

var testMpCases = []struct {
	name        string
	destination string
}{
	{
		name:        "DN",
		destination: ONE_IP,
	},
	{
		name:        "MEC",
		destination: MEC_IP,
	},
}

func TestULCLMultiPathUe1(t *testing.T) {
	fru := freeRanUE.NewFreeRanUe()
	fru.Activate()
	defer fru.Deactivate()

	time.Sleep(5 * time.Second)

	for _, testCase := range testMpCases {
		t.Run(testCase.name, func(t *testing.T) {
			if err := pinger.Pinger(testCase.destination, NIC_1); err != nil {
				t.Errorf("Ping %s failed: expected ping success, but got %v", testCase.destination, err)
			}
		})
	}
}

func TestULCLMultiPathUe2(t *testing.T) {
	fru := freeRanUE.NewFreeRanUe()
	fru.Activate()
	defer fru.Deactivate()

	time.Sleep(5 * time.Second)

	for _, testCase := range testMpCases {
		t.Run(testCase.name, func(t *testing.T) {
			if err := pinger.Pinger(testCase.destination, NIC_2); err != nil {
				t.Errorf("Ping %s failed: expected ping success, but got %v", testCase.destination, err)
			}
		})
	}
}
