package TestComm

import (
	"github.com/free5gc/ngap/aper"
	ngapIE "github.com/free5gc/ngap/ie"
	"github.com/free5gc/openapi/models"
)

const (
	N2_SmInfo        = "N2 Sm Info"
	N1_NAS_SM        = "N1 NAS SM"
	FAIL_NOTI        = "Failure Notification"
	SKIP_N1          = "Skip N1Msg"
	PDU_SETUP_REQ    = "pdu resource setup request"
	PDU_SETUP_REQ_11 = "pdu resource setup request 11"
)

var ConsumerAMFN1N2MessageTransferRequsetTable = make(map[string]*models.Amf_Comm_N1N2MessageTransferReqData)

func init() {
	ConsumerAMFN1N2MessageTransferRequsetTable[N2_SmInfo] = &models.Amf_Comm_N1N2MessageTransferReqData{
		N2InfoContainer: &models.Amf_Comm_N2InfoContainer{
			N2InformationClass: models.Amf_Comm_N2InformationClass_SM,
			SmInfo: &models.Amf_Comm_N2SmInformation{
				PduSessionId: 10,
				N2InfoContent: &models.Amf_Comm_N2InfoContent{
					NgapIeType: models.Amf_Comm_NgapIeType_PDU_RES_REL_CMD,
					NgapData: &models.RefToBinaryData{
						ContentId: "N2SmInfo",
					},
				},
			},
		},
		PduSessionId: 10,
	}
	ConsumerAMFN1N2MessageTransferRequsetTable[N1_NAS_SM] = &models.Amf_Comm_N1N2MessageTransferReqData{
		PduSessionId: 10,
		N1MessageContainer: &models.Amf_Comm_N1MessageContainer{
			N1MessageClass: models.Amf_Comm_N1MessageClass_SM,
			N1MessageContent: &models.RefToBinaryData{
				ContentId: "N1Msg",
			},
		},
	}
	ConsumerAMFN1N2MessageTransferRequsetTable[SKIP_N1] = &models.Amf_Comm_N1N2MessageTransferReqData{
		N1MessageContainer: &models.Amf_Comm_N1MessageContainer{
			N1MessageClass: models.Amf_Comm_N1MessageClass_SM,
			N1MessageContent: &models.RefToBinaryData{
				ContentId: "N1Msg",
			},
		},
		SkipInd: true,
	}
	ConsumerAMFN1N2MessageTransferRequsetTable[FAIL_NOTI] = &models.Amf_Comm_N1N2MessageTransferReqData{
		N1MessageContainer: &models.Amf_Comm_N1MessageContainer{
			N1MessageClass: models.Amf_Comm_N1MessageClass_SM,
			N1MessageContent: &models.RefToBinaryData{
				ContentId: "N1Msg",
			},
		},
		N1n2FailureTxfNotifURI: "https://localhost:8082/n1n2MessageError",
	}
	ConsumerAMFN1N2MessageTransferRequsetTable[PDU_SETUP_REQ] = &models.Amf_Comm_N1N2MessageTransferReqData{
		N1MessageContainer: &models.Amf_Comm_N1MessageContainer{
			N1MessageClass: models.Amf_Comm_N1MessageClass_SM,
			N1MessageContent: &models.RefToBinaryData{
				ContentId: "N1Msg",
			},
		},
		N2InfoContainer: &models.Amf_Comm_N2InfoContainer{
			N2InformationClass: models.Amf_Comm_N2InformationClass_SM,
			SmInfo: &models.Amf_Comm_N2SmInformation{
				PduSessionId: 10,
				N2InfoContent: &models.Amf_Comm_N2InfoContent{
					NgapIeType: models.Amf_Comm_NgapIeType_PDU_RES_SETUP_REQ,
					NgapData: &models.RefToBinaryData{
						ContentId: "N2SmInfo",
					},
				},
				SNssai: &models.Snssai{
					Sst: 1,
					Sd:  "010203",
				},
			},
		},
		PduSessionId: 10,
	}
	ConsumerAMFN1N2MessageTransferRequsetTable[PDU_SETUP_REQ_11] = &models.Amf_Comm_N1N2MessageTransferReqData{
		N2InfoContainer: &models.Amf_Comm_N2InfoContainer{
			N2InformationClass: models.Amf_Comm_N2InformationClass_SM,
			SmInfo: &models.Amf_Comm_N2SmInformation{
				PduSessionId: 11,
				N2InfoContent: &models.Amf_Comm_N2InfoContent{
					NgapIeType: models.Amf_Comm_NgapIeType_PDU_RES_SETUP_REQ,
					NgapData: &models.RefToBinaryData{
						ContentId: "N2SmInfo",
					},
				},
				SNssai: &models.Snssai{
					Sst: 1,
					Sd:  "010203",
				},
			},
		},
		PduSessionId: 11,
	}
}

var N2InfoTable = make(map[models.Amf_Comm_NgapIeType]interface{})

func init() {
	N2InfoTable[models.Amf_Comm_NgapIeType_PDU_RES_REL_CMD] = buildPDUSessionResourceReleaseCommandTransfer()
	// pdu := buildPDUSessionResourceReleaseCommand()
	// rawData, err := ngap.Encoder(pdu)
	// if err != nil {
	// 	log.Fatal(err)
	// }
	// fmt.Printf("	out : %0x\n", rawData)
	// transfer := GetPDUSessionResourceReleaseCommandTransfer()
	// var data ngapIE.PDUSessionResourceReleaseCommandTransfer
	// aper.UnmarshalWithParams(*transfer, &data, "valueExt")
	// spew.Dump(data)

}

func buildPDUSessionResourceReleaseCommandTransfer() (data ngapIE.PDUSessionResourceReleaseCommandTransfer) {
	data.Cause = &ngapIE.Cause{
		Choice: &ngapIE.CauseMisc{Value: ngapIE.CauseMiscPresentHardwareFailure},
	}
	return
}

func GetPDUSessionResourceReleaseCommandTransfer() []byte {
	transfer, ok := N2InfoTable[models.Amf_Comm_NgapIeType_PDU_RES_REL_CMD].(ngapIE.PDUSessionResourceReleaseCommandTransfer)
	if !ok {
		return nil
	}
	data := aper.NewPerBitData(nil)
	if err := transfer.Write(data); err != nil {
		return nil
	}
	return data.Bytes()
}
