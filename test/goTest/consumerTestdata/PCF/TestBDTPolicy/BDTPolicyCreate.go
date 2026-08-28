package TestBDTPolicy

import (
	"time"

	"github.com/free5gc/openapi/models"
)

func GetCreateTestData() models.Pcf_BDTPolCtrl_BdtReqData {
	startTime := time.Now()
	stopTime := startTime.Add(10 * time.Minute)
	bdtReqData := models.Pcf_BDTPolCtrl_BdtReqData{
		AspId: "123456",
		DesTimeInt: &models.Nef_TimeWindow{
			StartTime: &startTime,
			StopTime:  &stopTime,
		},
		NumOfUes: 1,
		VolPerUe: &models.Nef_UsageThreshold{
			Duration:       1,
			TotalVolume:    1,
			DownlinkVolume: 1,
			UplinkVolume:   1,
		},
		NwAreaInfo: &models.Pcf_BDTPolCtrl_NetworkAreaInfo{
			Tais: []models.Tai{
				{
					PlmnId: &models.PlmnId{
						Mcc: "208",
						Mnc: "93",
					},
					Tac: "000001",
				},
			},
			Ncgis: []models.Ncgi{
				{
					PlmnId: &models.PlmnId{
						Mcc: "208",
						Mnc: "93",
					},
					NrCellId: "000000001",
				},
			},
			GRanNodeIds: []models.GlobalRanNodeId{
				{
					PlmnId: &models.PlmnId{
						Mcc: "208",
						Mnc: "93",
					},
					GNbId: &models.GNbId{
						BitLength: 24,
						GNBValue:  "000001",
					},
				},
			},
		},
		SuppFeat: "",
	}

	return bdtReqData
}

func GetUpdateTestData() models.Pcf_BDTPolCtrl_BdtPolicyDataPatch {
	bdtPolicyDataPatch := models.Pcf_BDTPolCtrl_BdtPolicyDataPatch{
		SelTransPolicyId: 1,
	}
	return bdtPolicyDataPatch
}
