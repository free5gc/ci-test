package test

import (
	"os/exec"
	"testing"
	"time"

	packetRusher "test/packetRusher"
	pinger "test/pinger"
)

func TestULCLTrafficInfluence(t *testing.T) {
	// PacketRusher
	pr := packetRusher.NewPacketRusher()
	pr.Activate()
	defer pr.Deactivate()

	time.Sleep(3 * time.Second)

	// before TI
	t.Run("Before TI", func(t *testing.T) {
		pingN6gwSuccessMecFailed(t)
	})

	// post TI
	tiOperation(t, "put")

	// after TI
	t.Run("After TI", func(t *testing.T) {
		pingN6gwFailedMecSuccess(t)
	})

	// delete TI
	tiOperation(t, "delete")

	// reset TI
	t.Run("Reset TI", func(t *testing.T) {
		pingN6gwSuccessMecFailed(t)
	})

	// flow level ping
	t.Run("Flow Level Ping", func(t *testing.T) {
		pingOneOneOneOne(t)
	})

	// check charging record
	t.Run("Check Charging Record", func(t *testing.T) {
		checkChargingRecord(t)
	})
}

func pingN6gwSuccessMecFailed(t *testing.T) {
	err := pinger.Pinger(N6GW_IP, NIC_1)
	if err != nil {
		t.Errorf("Ping n6gw failed: expected ping success, but got %v", err)
	}
	err = pinger.Pinger(MEC_IP, NIC_1)
	if err == nil {
		t.Errorf("Ping mec failed: expected ping failed, but got %v", err)
	}
}

func pingN6gwFailedMecSuccess(t *testing.T) {
	err := pinger.Pinger(N6GW_IP, NIC_1)
	if err == nil {
		t.Errorf("Ping n6gw failed: expected ping failed, but got %v", err)
	}
	err = pinger.Pinger(MEC_IP, NIC_1)
	if err != nil {
		t.Errorf("Ping mec failed: expected ping sucess, but got %v", err)
	}
}

func pingOneOneOneOne(t *testing.T) {
	err := pinger.Pinger(ONE_IP, NIC_1)
	if err != nil {
		t.Errorf("Ping one.one.one.one failed: expected ping success, but got %v", err)
	}
}

func tiOperation(t *testing.T, operation string) {
	cmd := exec.Command("bash", "../api-udr-ti-data-action.sh", operation)
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Errorf("TI operation failed: expected %s success, but got %v, output: %s", operation, err, output)
	}
	time.Sleep(300 * time.Millisecond)
}
