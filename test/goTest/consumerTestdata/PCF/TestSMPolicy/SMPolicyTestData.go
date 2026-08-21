package TestSMPolicy

import (
	"time"

	"github.com/free5gc/openapi/models"
)

func CreateTestData() models.Pcf_SMPolCtrl_SmPolicyContextData {
	t := time.Date(2000, 2, 1, 12, 30, 0, 0, time.UTC)
	// timeNow := time.Now()
	smReqData := models.Pcf_SMPolCtrl_SmPolicyContextData{
		NotificationUri: "https://127.0.0.1:29502/nsmf-callback/v1/sm-policies/imsi-208930000007487-1",
		// AccNetChId: &models.Pcf_SMPolCtrl_AccNetChId{
		// 	AccNetChaIdValue: 0,
		// 	RefPccRuleIds:    []string{"A", "B", "C"},
		// 	SessionChScope:   true,
		// },
		// ChargEntityAddr: &models.Pcf_SMPolCtrl_AccNetChargingAddress{
		// 	AnChargIpv4Addr: "198.51.100.1",
		// 	AnChargIpv6Addr: "2001:db8:85a3::8a2e:370:7334",
		// },
		Supi:       "imsi-208930000007487",
		SuppFeat:   "3fff",
		Pei:        "123456789123456",
		RatType:    models.RatType_NR,
		AccessType: models.AccessType_3_GPP_ACCESS,
		// Gpsi:                    "string1",
		// InterGrpIds:             []string{"A", "B", "C"},
		PduSessionId: 1,
		// Chargingcharacteristics: "string",
		Dnn:            "internet",
		PduSessionType: models.PduSessionType_IPV4,
		ServingNetwork: &models.PlmnIdNid{
			Mcc: "208",
			Mnc: "93",
		},
		UserLocationInfo: &models.UserLocation{
			NrLocation: &models.NrLocation{
				Tai: &models.Tai{
					PlmnId: &models.PlmnId{
						Mcc: "208",
						Mnc: "93",
					},
					Tac: "000001",
				},
				Ncgi: &models.Ncgi{
					PlmnId: &models.PlmnId{
						Mcc: "208",
						Mnc: "93",
					},
					NrCellId: "000000001",
				},
				AgeOfLocationInformation: 123,
				// UeLocationTimestamp:      "2019-04-15T09:47:35.505Z",
				UeLocationTimestamp: &t,
				GlobalGnbId: &models.GlobalRanNodeId{
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
		UeTimeZone:        "+08:00+1h",
		Ipv4Address:       "45.45.0.2",
		Ipv6AddressPrefix: "2001:db8:abcd:12::0/64",
		IpDomain:          "free5gc.org",
		SubsSessAmbr: &models.Ambr{
			Uplink:   "800 Kbps",
			Downlink: "1000 Kbps",
		},
		SubsDefQos: &models.SubscribedDefaultQos{
			Var5qi: 9,
			Arp: &models.Arp{
				PriorityLevel: 8,
			},
			PriorityLevel: 8,
		},
		Online:                 false,
		Offline:                false,
		Var3gppPsDataOffStatus: false,
		// RefQosIndication:       true,
		TraceReq: &models.TraceData{
			TraceRef:                 "string",
			NeTypeList:               "string",
			EventList:                "string",
			CollectionEntityIpv4Addr: "198.51.100.1",
			CollectionEntityIpv6Addr: "2001:db8:85a3::8a2e:370:7334",
			InterfaceList:            "string",
		},
		SliceInfo: &models.Snssai{
			Sst: 1,
			Sd:  "010203",
		},
		QosFlowUsage: models.Pcf_SMPolCtrl_QosFlowUsage_GENERAL,
	}
	return smReqData
}

func UpdateTestData(trigger []models.Pcf_SMPolCtrl_PolicyControlRequestTrigger, op *models.Pcf_SMPolCtrl_RuleOperation) models.Pcf_SMPolCtrl_SmPolicyUpdateContextData {
	t := time.Date(2000, 2, 1, 12, 30, 0, 0, time.UTC)
	data := models.Pcf_SMPolCtrl_SmPolicyUpdateContextData{
		RepPolicyCtrlReqTriggers: trigger,
		AccessType:               models.AccessType_3_GPP_ACCESS,
		ServingNetwork: &models.PlmnIdNid{
			Mnc: "208",
			Mcc: "93",
		},
		RatType:                models.RatType_NR,
		RelIpv4Address:         "45.45.0.2",
		Ipv4Address:            "45.45.0.3",
		Var3gppPsDataOffStatus: false,
		SubsDefQos: &models.SubscribedDefaultQos{
			Var5qi: 8,
			Arp: &models.Arp{
				PriorityLevel: 8,
			},
			PriorityLevel: 8,
		},
		SubsSessAmbr: &models.Ambr{
			Uplink:   "1.2 Mbps",
			Downlink: "1.3 Mbps",
		},
		UserLocationInfo: &models.UserLocation{
			NrLocation: &models.NrLocation{
				Tai: &models.Tai{
					PlmnId: &models.PlmnId{
						Mcc: "208",
						Mnc: "93",
					},
					Tac: "000002",
				},
				Ncgi: &models.Ncgi{
					PlmnId: &models.PlmnId{
						Mcc: "208",
						Mnc: "93",
					},
					NrCellId: "000000001",
				},
				AgeOfLocationInformation: 123,
				// UeLocationTimestamp:      "2019-04-15T09:47:35.505Z",
				UeLocationTimestamp: &t,
				GlobalGnbId: &models.GlobalRanNodeId{
					PlmnId: &models.PlmnId{
						Mcc: "208",
						Mnc: "93",
					},
					GNbId: &models.GNbId{
						BitLength: 24,
						GNBValue:  "000002",
					},
				},
			},
		},
		ServNfId: &models.Pcf_SMPolCtrl_ServingNfIdentity{
			Guami: &models.Guami{
				PlmnId: &models.PlmnIdNid{
					Mcc: "208",
					Mnc: "93",
				},
				AmfId: "cafe00",
			},
		},
		UeTimeZone: "+08:00+2h",
	}
	if op != nil {
		ueInitResReq := models.Pcf_SMPolCtrl_UeInitiatedResourceRequest{
			PccRuleId:  "PccRuleId-1",
			RuleOp:     *op,
			Precedence: 1,
			ReqQos: &models.Pcf_SMPolCtrl_RequestedQos{
				Var5qi: 2,
				GbrDl:  "30 Mbps",
				GbrUl:  "30.5 Mbps",
			},
			PackFiltInfo: []models.Pcf_SMPolCtrl_PacketFilterInfo{
				{
					PackFiltCont:  "permit out ip from any to assigned",
					FlowDirection: models.Pcf_SMPolCtrl_FlowDirection_DOWNLINK,
				},
			},
		}
		switch *op {
		case models.Pcf_SMPolCtrl_RuleOperation_CREATE_PCC_RULE:
		case models.Pcf_SMPolCtrl_RuleOperation_DELETE_PCC_RULE:
			data.UeInitResReq = &models.Pcf_SMPolCtrl_UeInitiatedResourceRequest{
				RuleOp:    *op,
				PccRuleId: "PccRuleId-1",
			}
			return data
		case models.Pcf_SMPolCtrl_RuleOperation_MODIFY_PCC_RULE_AND_ADD_PACKET_FILTERS:
			ueInitResReq.ReqQos.GbrDl = "30.5 Mbps"
			ueInitResReq.PackFiltInfo[0] = models.Pcf_SMPolCtrl_PacketFilterInfo{
				PackFiltCont:  "permit out ip from any to assigned",
				FlowDirection: models.Pcf_SMPolCtrl_FlowDirection_UPLINK,
			}
		case models.Pcf_SMPolCtrl_RuleOperation_MODIFY_PCC_RULE_AND_REPLACE_PACKET_FILTERS:
			ueInitResReq.PackFiltInfo[0].PackFiltCont = "permit out tcp from any 8080 to assigned"
			ueInitResReq.ReqQos = nil
		case models.Pcf_SMPolCtrl_RuleOperation_MODIFY_PCC_RULE_AND_DELETE_PACKET_FILTERS:
			ueInitResReq.ReqQos = nil
			ueInitResReq.PackFiltInfo[0].PackFiltId = "PackFiltId-1"
		case models.Pcf_SMPolCtrl_RuleOperation_MODIFY_PCC_RULE_WITHOUT_MODIFY_PACKET_FILTERS:
			ueInitResReq.ReqQos.GbrUl = "50 Mbps"
			ueInitResReq.ReqQos.GbrDl = "50.5 Mbps"
		}
		data.UeInitResReq = &ueInitResReq
	}
	return data
}
func DeldateTestData() models.Pcf_SMPolCtrl_SmPolicyDeleteData {
	smDelData := models.Pcf_SMPolCtrl_SmPolicyDeleteData{
		UserLocationInfo: &models.UserLocation{
			EutraLocation: &models.EutraLocation{
				Tai: &models.Tai{
					PlmnId: &models.PlmnId{
						Mcc: "string",
						Mnc: "string",
					},
				},
			},
		},
	}
	return smDelData
}

func CreateTestData12345() models.Pcf_SMPolCtrl_SmPolicyContextData {
	smReqDataTest12345 := models.Pcf_SMPolCtrl_SmPolicyContextData{
		PduSessionId:    12345,
		Dnn:             "string",
		NotificationUri: "string",
		PduSessionType:  "string",
		SliceInfo: &models.Snssai{
			Sst: 1,
			Sd:  "string",
		},
		Supi: "string2",
		Gpsi: "string2",
		ChargEntityAddr: &models.Pcf_SMPolCtrl_AccNetChargingAddress{
			AnChargIpv4Addr: "198.51.100.1",
			AnChargIpv6Addr: "2001:db8:85a3::8a2e:370:7334",
		},
		Ipv4Address:       "198.51.100.1",
		Ipv6AddressPrefix: "2001:db8:abcd:12::0/64",
	}
	return smReqDataTest12345
}

func ChangeTestData() models.Udr_DR_PolicyDataChangeNotification {
	changeDataTest12345 := models.Udr_DR_PolicyDataChangeNotification{
		SmPolicyData: &models.Udr_DR_SmPolicyData{
			SmPolicySnssaiData: map[string]models.Udr_DR_SmPolicySnssaiData{
				"Snssai": {Snssai: &models.Snssai{
					Sd: "string",
				}},
				"1string": {SmPolicyDnnData: map[string]models.Udr_DR_SmPolicyDnnData{
					"string": {Ipv4Index: 1, Online: false, Offline: false},
				}},
			},
		},
	}
	return changeDataTest12345
}
