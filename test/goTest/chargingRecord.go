package test

import (
	"encoding/json"
	"os/exec"
	"strings"
	"testing"
)

func checkChargingRecord(t *testing.T) {
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

	var chargingRecords []map[string]interface{}
	if err := json.Unmarshal([]byte(jsonLine), &chargingRecords); err != nil {
		t.Errorf("Failed to parse charging record JSON: %v\nJSON content: %s", err, jsonLine)
		return
	}

	if len(chargingRecords) == 0 {
		t.Error("No charging records found")
		return
	}

	t.Run("Check Session Level Charging Record", func(t *testing.T) {
		checkXLevelChargingRecord(t, chargingRecords, "Session", "")
	})

	t.Run("Check Flow Level Charging Record", func(t *testing.T) {
		checkXLevelChargingRecord(t, chargingRecords, "Flow", "internet")
	})
}

func checkXLevelChargingRecord(t *testing.T, chargingRecords []map[string]interface{}, level string, dnn string) {
	for _, record := range chargingRecords {
		if record["Dnn"] == dnn {
			if record["TotalVol"].(float64) != 0 {
				return
			}
			t.Errorf("%s level charging record is empty", level)
		}
	}
	t.Errorf("No %s level charging record found", level)
}
