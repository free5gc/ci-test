package TestAmf

import (
	"github.com/google/uuid"

	"github.com/free5gc/openapi/models"
)

func BuildSmfNfProfile() (uuId string, profile models.Nrf_NFMgmt_NFProfile) {
	uuId = uuid.New().String()
	profile = models.Nrf_NFMgmt_NFProfile{
		NfInstanceId: uuId,
		NfType:       models.Nrf_NFMgmt_NFType_SMF,
		NfStatus:     models.Nrf_NFMgmt_NFStatus_REGISTERED,
		SNssais: []models.ExtSnssai{
			{
				Sst: 1,
				Sd:  "010203",
			},
		},
		PlmnList: []models.PlmnId{
			{
				Mcc: "208",
				Mnc: "93",
			},
		},
		NfServices: []models.Nrf_NFMgmt_NFService{
			{

				ServiceInstanceId: "1",
				ServiceName:       models.Nrf_NFMgmt_ServiceName_NSMF_PDUSESSION,
				Scheme:            models.UriScheme_HTTPS,
				NfServiceStatus:   models.Nrf_NFMgmt_NFServiceStatus_REGISTERED,
				Versions: []models.Nrf_NFMgmt_NFServiceVersion{
					{
						ApiVersionInUri: "v1",
						ApiFullVersion:  "1.0.0",
					},
				},
				ApiPrefix: "https://localhost:29502",
				IpEndPoints: []models.Nrf_NFMgmt_IpEndPoint{
					{
						Ipv4Address: "127.0.0.1",
						Port:        29502,
					},
				},
			},
		},
		SmfInfo: &models.Nrf_NFMgmt_SmfInfo{
			SNssaiSmfInfoList: []models.Nrf_NFMgmt_SnssaiSmfInfoItem{
				{
					SNssai: &models.ExtSnssai{
						Sst: 1,
						Sd:  "010203",
					},
					DnnSmfInfoList: []models.Nrf_NFMgmt_DnnSmfInfoItem{
						{
							Dnn: "internet",
						},
					},
				},
			},
		},
	}
	return

}
