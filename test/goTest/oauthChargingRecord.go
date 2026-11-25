package test

import (
	"encoding/json"
	"os/exec"
	"strings"
	"testing"

	"github.com/free5gc/webconsole/backend/WebUI"
)

func checkRegPduChargingRecord(t *testing.T, snssai string) {
	cmd := exec.Command("bash", "../api-webconsole-charging-record.sh", "get", "../json/webconsole-login-data.json")
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Errorf("Get charging record failed: %v, output: %s", err, output)
		return
	}

	outputStr := string(output)

	lines := strings.Split(outputStr, "\n")
	var jsonLine string
	for i := len(lines) - 1; i >= 0; i-- {
		if strings.TrimSpace(lines[i]) != "" {
			jsonLine = lines[i]
			break
		}
	}

	var chargingRecords []WebUI.RatingGroupDataUsage
	if err := json.Unmarshal([]byte(jsonLine), &chargingRecords); err != nil {
		t.Errorf("Failed to parse charging record JSON: %v\nJSON content: %s", err, jsonLine)
		return
	}

	if len(chargingRecords) == 0 {
		t.Error("No charging records found")
		return
	}

	t.Run("Check Session Level Charging Record", func(t *testing.T) {
		requireUsage(t, chargingRecords, snssai, "", "")
	})

	t.Run("Check Flow Level Charging Record", func(t *testing.T) {
		requireUsage(t, chargingRecords, snssai, "internet", ONE_IP+"/32")
	})
}

func requireUsage(t *testing.T, records []WebUI.RatingGroupDataUsage, snssai, dnn, filter string) {
	t.Helper()
	for _, record := range records {
		if record.Supi == UE_IMSI && record.Snssai == snssai && record.Dnn == dnn &&
			record.Filter == filter && record.TotalVol > 0 {
			return
		}
	}
	t.Errorf("missing positive charging volume for SUPI %s, S-NSSAI %s, DNN %q, filter %q",
		UE_IMSI, snssai, dnn, filter)
}
