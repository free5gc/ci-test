package TestPolicyAuthorization

import (
	"github.com/free5gc/openapi/models"
)

func GetPostAppSessionsData_Normal() models.Pcf_PolAuth_AppSessionContext {
	PostAppSessionsData := models.Pcf_PolAuth_AppSessionContext{
		AscReqData: &models.Pcf_PolAuth_AppSessionContextReqData{
			AfRoutReq: &models.Pcf_PolAuth_AfRoutingRequirement{},
			Dnn:       "internet",
			SliceInfo: &models.Snssai{
				Sst: 1,
				Sd:  "010203",
			},
			MedComponents: map[string]models.Pcf_PolAuth_MediaComponent{
				"1": {
					MedCompN: 1,
					MarBwDl:  "400 Mbps",
					MarBwUl:  "400 Mbps",
					MirBwDl:  "20 Mbps",
					MirBwUl:  "20 Mbps",
					MedType:  models.Pcf_PolAuth_MediaType_AUDIO,
					FStatus:  models.Pcf_PolAuth_FlowStatus_ENABLED,
					MedSubComps: map[string]models.Pcf_PolAuth_MediaSubComponent{
						"1": {
							FNum:    1,
							FDescs:  []string{"permit out ip from 127.0.0.1 to 45.45.0.2"},
							FStatus: models.Pcf_PolAuth_FlowStatus_ENABLED,
						},
					},
				},
			},
			EvSubsc: &models.Pcf_PolAuth_EventsSubscReqData{
				Events: []models.Pcf_PolAuth_AfEventSubscription{
					{
						Event:       models.Pcf_PolAuth_AfEvent_ACCESS_TYPE_CHANGE,
						NotifMethod: models.Pcf_PolAuth_AfNotifMethod_EVENT_DETECTION,
					},
					{
						Event: models.Pcf_PolAuth_AfEvent_QOS_NOTIF,
					},
					{
						Event: models.Pcf_PolAuth_AfEvent_PLMN_CHG,
					},
					{
						Event: models.Pcf_PolAuth_AfEvent_FAILED_RESOURCES_ALLOCATION,
					},
					{
						Event: models.Pcf_PolAuth_AfEvent_SUCCESSFUL_RESOURCES_ALLOCATION,
					},
					{
						Event: models.Pcf_PolAuth_AfEvent_USAGE_REPORT,
					},
				},
				NotifUri: "https://127.0.0.1:12345",
				UsgThres: &models.Nef_UsageThreshold{
					Duration:    100,
					TotalVolume: 30000,
				},
			},
			NotifUri: "https://127.0.0.1:12345",
			SuppFeat: "5", //b'0111'
			Supi:     "imsi-208930000007487",
			UeIpv4:   "45.45.0.2",
		},
	}
	return PostAppSessionsData
}

func GetPostAppSessionsData_AFInfluenceOnTrafficRouting() models.Pcf_PolAuth_AppSessionContext {
	PostAppSessionsData := models.Pcf_PolAuth_AppSessionContext{
		AscReqData: &models.Pcf_PolAuth_AppSessionContextReqData{
			AfAppId:  "edge",
			Dnn:      "internet",
			SuppFeat: "03",
			Supi:     "imsi-208930000007487",
			UeIpv4:   "10.60.0.1",
			SliceInfo: &models.Snssai{
				Sst: 1, Sd: "fedcba",
			},
			AfRoutReq: &models.Pcf_PolAuth_AfRoutingRequirement{
				AppReloc: false,
				UpPathChgSub: &models.Pcf_SMPolCtrl_UpPathChgEvent{
					DnaiChgType:     models.DnaiChangeType_LATE,
					NotificationUri: "http://127.0.0.100:8000/nnef-callback/v1/traffic-influence/edge",
					NotifCorreId:    "1234",
				},
				RouteToLocs: []models.RouteToLocation{
					{
						Dnai:        "edge",
						RouteProfId: "MEC1",
					},
				},
			},
			NotifUri: "http://127.0.0.100:8000/nnef-callback/v1/applications/edge",
			IpDomain: "edgeIPDomain",
		},
	}
	return PostAppSessionsData
}

func GetPostAppSessionsData_Flow3() models.Pcf_PolAuth_AppSessionContext {
	PostAppSessionsData := GetPostAppSessionsData_Normal()
	medComp := PostAppSessionsData.AscReqData.MedComponents["1"]
	medComp.MedSubComps["2"] = models.Pcf_PolAuth_MediaSubComponent{
		FNum:    2,
		FDescs:  []string{"permit in ip from 127.0.0.2 to 45.45.0.2"},
		MarBwDl: "200 Mbps",
		FStatus: models.Pcf_PolAuth_FlowStatus_ENABLED,
	}
	medComp.MedSubComps["3"] = models.Pcf_PolAuth_MediaSubComponent{
		FNum:    3,
		FDescs:  []string{"permit inout ip from 127.0.0.3 to 45.45.0.2"},
		MarBwDl: "500 Mbps",
		FStatus: models.Pcf_PolAuth_FlowStatus_ENABLED,
	}
	PostAppSessionsData.AscReqData.MedComponents["1"] = medComp
	return PostAppSessionsData
}

func GetPostAppSessionsData_403Forbidden() models.Pcf_PolAuth_AppSessionContext {
	PostAppSessionsData := GetPostAppSessionsData_Normal()
	medComp := PostAppSessionsData.AscReqData.MedComponents["1"]
	medComp.MedSubComps["1"] = models.Pcf_PolAuth_MediaSubComponent{
		FNum:    1,
		FDescs:  []string{"permit in ip from 127.0.0.4 to 45.45.0.2"},
		FStatus: models.Pcf_PolAuth_FlowStatus_ENABLED,
	}
	medComp.MirBwUl = "500 Mbps"
	PostAppSessionsData.AscReqData.MedComponents["1"] = medComp
	return PostAppSessionsData
}

func GetPostAppSessionsData_400() models.Pcf_PolAuth_AppSessionContext {
	PostAppSessionsData := GetPostAppSessionsData_Normal()
	PostAppSessionsData.AscReqData.MedComponents = nil
	return PostAppSessionsData
}

func GetPostAppSessionsData_NoEvent() models.Pcf_PolAuth_AppSessionContext {
	PostAppSessionsData := GetPostAppSessionsData_Normal()
	PostAppSessionsData.AscReqData.EvSubsc = nil
	return PostAppSessionsData
}

func GetDeleteAppSession204Data() models.Pcf_PolAuth_AppSessionContext {
	DeleteAppSession204Data := models.Pcf_PolAuth_AppSessionContext{
		AscReqData: &models.Pcf_PolAuth_AppSessionContextReqData{
			Supi:     "123",
			NotifUri: "https://127.0.0.1:12345",
			SuppFeat: "0",
		},
		AscRespData: &models.Pcf_PolAuth_AppSessionContextRespData{},
		EvsNotif:    &models.Pcf_PolAuth_EventsNotification{},
	}
	return DeleteAppSession204Data
}

func GetUpdateEventsSubsc201Data() models.Pcf_PolAuth_EventsSubscReqData {
	UpdateEventsSubsc201Data := models.Pcf_PolAuth_EventsSubscReqData{
		Events: []models.Pcf_PolAuth_AfEventSubscription{
			{
				Event:       models.Pcf_PolAuth_AfEvent_ACCESS_TYPE_CHANGE,
				NotifMethod: models.Pcf_PolAuth_AfNotifMethod_EVENT_DETECTION,
			},
			{
				Event:       models.Pcf_PolAuth_AfEvent_PLMN_CHG,
				NotifMethod: models.Pcf_PolAuth_AfNotifMethod_EVENT_DETECTION,
			},
		},
		NotifUri: "https://127.0.0.1:12345",
	}
	return UpdateEventsSubsc201Data
}

func GetUpdateEventsSubsc200Data() models.Pcf_PolAuth_EventsSubscReqData {
	UpdateEventsSubsc200Data := models.Pcf_PolAuth_EventsSubscReqData{
		Events: []models.Pcf_PolAuth_AfEventSubscription{
			{
				Event:       models.Pcf_PolAuth_AfEvent_PLMN_CHG,
				NotifMethod: models.Pcf_PolAuth_AfNotifMethod_EVENT_DETECTION,
			},
		},
		NotifUri: "https://127.0.0.1:12345",
	}
	return UpdateEventsSubsc200Data
}

func GetUpdateEventsSubsc204Data() models.Pcf_PolAuth_EventsSubscReqData {
	UpdateEventsSubsc204Data := models.Pcf_PolAuth_EventsSubscReqData{
		Events: []models.Pcf_PolAuth_AfEventSubscription{
			{
				Event:       models.Pcf_PolAuth_AfEvent_SUCCESSFUL_RESOURCES_ALLOCATION,
				NotifMethod: models.Pcf_PolAuth_AfNotifMethod_EVENT_DETECTION,
			},
		},
		NotifUri: "https://127.0.0.1:12345",
	}
	return UpdateEventsSubsc204Data
}

func GetUpdateEventsSubsc400Data() models.Pcf_PolAuth_EventsSubscReqData {
	UpdateEventsSubsc400Data := models.Pcf_PolAuth_EventsSubscReqData{
		UsgThres: &models.Nef_UsageThreshold{
			Duration:       0,
			TotalVolume:    0,
			DownlinkVolume: 0,
			UplinkVolume:   0},
	}
	return UpdateEventsSubsc400Data
}

func GetModAppSession200Data() models.Pcf_PolAuth_AppSessionContextUpdateData {
	ModAppSession200Data := models.Pcf_PolAuth_AppSessionContextUpdateData{
		AfRoutReq: &models.Pcf_PolAuth_AfRoutingRequirementRm{
			AppReloc: true,
			RouteToLocs: []models.RouteToLocation{
				{
					Dnai: "Dnai",
					RouteInfo: &models.RouteInformation{
						Ipv4Addr:   "111.11.11.1",
						Ipv6Addr:   "222.22.22.2",
						PortNumber: 9999,
					},
					RouteProfId: "RouteProfId",
				},
			},
			UpPathChgSub: &models.Pcf_SMPolCtrl_UpPathChgEvent{},
		},
		EvSubsc: &models.Pcf_PolAuth_EventsSubscReqDataRm{
			NotifUri: "EvSubsc_NotifUri",
			Events: []models.Pcf_PolAuth_AfEventSubscription{
				{
					Event:       models.Pcf_PolAuth_AfEvent_ACCESS_TYPE_CHANGE,
					NotifMethod: models.Pcf_PolAuth_AfNotifMethod_EVENT_DETECTION,
				},
			},
			UsgThres: &models.Nef_UsageThresholdRm{
				Duration:    10,
				TotalVolume: 10,
			},
		},
		MedComponents: map[string]*models.Pcf_PolAuth_MediaComponentRm{
			"1": {
				MedCompN: 1,
				MarBwDl:  "40 Mbps",
				MarBwUl:  "40 Mbps",
				MirBwDl:  "20 Mbps",
				MirBwUl:  "20 Mbps",
				MedType:  models.Pcf_PolAuth_MediaType_AUDIO,
				FStatus:  models.Pcf_PolAuth_FlowStatus_ENABLED,
				MedSubComps: map[string]*models.Pcf_PolAuth_MediaSubComponentRm{
					"1": {
						FNum:    1,
						FDescs:  []string{"permit out ip from 127.0.0.9 to 45.45.0.2"},
						FStatus: models.Pcf_PolAuth_FlowStatus_ENABLED,
					},
				},
			},
		},
	}
	return ModAppSession200Data
}

func GetModAppSession403Data() models.Pcf_PolAuth_AppSessionContextUpdateData {
	ModAppSession403Data := models.Pcf_PolAuth_AppSessionContextUpdateData{}
	return ModAppSession403Data
}
