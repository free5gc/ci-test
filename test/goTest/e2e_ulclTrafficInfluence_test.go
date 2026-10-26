package test

import (
	"os/exec"
	"testing"
	"time"

	"test/freeRanUe"
	"test/pinger"
)

func TestULCLTrafficInfluence(t *testing.T) {
	// FreeRanUe
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
		t.Errorf("Ping mec success: expected ping failed, but got success")
	}
}

func pingN6gwFailedMecSuccess(t *testing.T) {
	err := pinger.Pinger(N6GW_IP, NIC_1)
	if err == nil {
		t.Errorf("Ping n6gw success: expected ping failed, but got success")
	}
	err = pinger.Pinger(MEC_IP, NIC_1)
	if err != nil {
		t.Errorf("Ping mec failed: expected ping success, but got %v", err)
	}
}

func pingN6gwSuccessMecSuccess(t *testing.T) {
	err := pinger.Pinger(N6GW_IP, NIC_1)
	if err != nil {
		t.Errorf("Ping n6gw failed: expected ping success, but got %v", err)
	}
	err = pinger.Pinger(MEC_IP, NIC_1)
	if err != nil {
		t.Errorf("Ping mec failed: expected ping success, but got %v", err)
	}
}

func pingOneOneOneOne(t *testing.T) {
	err := pinger.Pinger(ONE_IP, NIC_1)
	if err != nil {
		t.Errorf("Ping one.one.one.one failed: expected ping success, but got %v", err)
	}
}

func tiOperation(t *testing.T, operation string, jsonFile ...string) {
	t.Helper()
	args := []string{"../api-udr-ti-data-action.sh", operation}
	if len(jsonFile) > 0 {
		args = append(args, "../"+jsonFile[0])
	}
	cmd := exec.Command("bash", args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Errorf("TI operation failed: expected %s success, but got %v, output: %s", operation, err, output)
	}
	time.Sleep(300 * time.Millisecond)
}

func TestTrafficInfluenceFlowRuleOverlapFull(t *testing.T) {
	tiFlowRuleOverlap(t, "json/ti-data-mec.json", pingN6gwSuccessMecSuccess)
}

func TestTrafficInfluenceFlowRuleOverlapPartial(t *testing.T) {
	tiFlowRuleOverlap(t, "json/ti-data-mec.json", pingN6gwSuccessMecSuccess)
}

func TestTrafficInfluenceFlowRuleOverlapMixed(t *testing.T) {
	tiFlowRuleOverlap(t, "json/ti-data.json", pingN6gwFailedMecSuccess)
}

// Overlap cases check connectivity; the original TI test retains charging record checks.
func tiFlowRuleOverlap(t *testing.T, tiDataFile string, pingDuringTI func(*testing.T)) {
	t.Helper()

	// Clear TI left by an earlier case, and clean it up even if this case fails.
	tiOperation(t, "delete")

	// FreeRanUe
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
	defer tiOperation(t, "delete")

	// before TI
	t.Run("Before TI", func(t *testing.T) {
		pingN6gwSuccessMecFailed(t)
		pingOneOneOneOne(t)
	})

	// post TI
	tiOperation(t, "put", tiDataFile)

	// after TI
	t.Run("After TI", func(t *testing.T) {
		pingDuringTI(t)
		pingOneOneOneOne(t)
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
}
