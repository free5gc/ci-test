package test

import (
	"os/exec"
	"testing"
	"time"

	freeRanUE "test/freeRanUE"
	pinger "test/pinger"
)

func TestULCLTrafficInfluence(t *testing.T) {
	// FreeRanUe
	fru := freeRanUE.NewFreeRanUe()
	fru.Activate()
	defer fru.Deactivate()

	waitForNicReady(t, NIC_1, 20*time.Second)

	// Ensure residual TI data from previous runs does not flip baseline route behavior.
	tiOperation(t, "delete")
	time.Sleep(1 * time.Second)

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
	if err := expectPingResultWithRetry(N6GW_IP, NIC_1, true, 8, time.Second); err != nil {
		t.Errorf("Ping n6gw failed: expected ping success, but got %v", err)
	}
	if err := expectPingResultWithRetry(MEC_IP, NIC_1, false, 8, time.Second); err != nil {
		t.Errorf("Ping mec success: expected ping failed, but got %v", err)
	}
}

func pingN6gwFailedMecSuccess(t *testing.T) {
	if err := expectPingResultWithRetry(N6GW_IP, NIC_1, false, 8, time.Second); err != nil {
		t.Errorf("Ping n6gw success: expected ping failed, but got %v", err)
	}
	if err := expectPingResultWithRetry(MEC_IP, NIC_1, true, 8, time.Second); err != nil {
		t.Errorf("Ping mec failed: expected ping success, but got %v", err)
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
	time.Sleep(2 * time.Second)
}

func waitForNicReady(t *testing.T, nic string, timeout time.Duration) {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		cmd := exec.Command("ip", "link", "show", nic)
		if err := cmd.Run(); err == nil {
			return
		}
		time.Sleep(500 * time.Millisecond)
	}
	t.Fatalf("Network interface %s not ready within %v", nic, timeout)
}

func expectPingResultWithRetry(dstIP string, nic string, shouldSucceed bool, attempts int, interval time.Duration) error {
	var lastErr error

	for i := 0; i < attempts; i++ {
		err := pinger.Pinger(dstIP, nic)
		if shouldSucceed {
			if err == nil {
				return nil
			}
			lastErr = err
		} else {
			if err != nil {
				return nil
			}
			lastErr = exec.ErrNotFound
		}
		time.Sleep(interval)
	}

	if shouldSucceed {
		return lastErr
	}

	return exec.ErrNotFound
}
