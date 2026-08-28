package TestComm

import (
	"github.com/free5gc/openapi/models"
)

const (
	CreateUEContext403           = "CreateUEContext403"
	CreateUEContext201           = "CreateUEContext201"
	UeContextRelease404          = "UeContextRelease404"
	UeContextRelease201          = "UeContextRelease201"
	UeContextTransfer404         = "UeContextTransfer404"
	UeContextTransferINIT_REG200 = "UeContextTransferINIT_REG200"
	UeContextTransferMOBI_REG200 = "UeContextTransferMOBI_REG200"
	AssignEbiData403             = "AssignEbiData403"
	AssignEbiData200             = "AssignEbiData200"
	RegistrationStatusUpdate404  = "RegistrationStatusUpdate404"
	RegistrationStatusUpdate200  = "RegistrationStatusUpdate200"
)

var ConsumerAMFCreateUEContextRequsetTable = make(map[string]models.CreateUEContextRequestBody)

func init() {
	ConsumerAMFCreateUEContextRequsetTable[CreateUEContext403] = models.CreateUEContextRequestBody{
		JsonData: &models.Amf_Comm_UeContextCreateData{
			UeContext: &models.Amf_Comm_UeContext{
				Supi: "imsi-208930000007487",
			},
			TargetId:           &models.Amf_Comm_NgRanTargetId{},
			SourceToTargetData: &models.Amf_Comm_N2InfoContent{},
			PduSessionList:     []models.Amf_Comm_N2SmInformation{},
			N2NotifyUri:        "127.0.0.1",
			UeRadioCapability:  nil,
			NgapCause:          nil,
			SupportedFeatures:  "",
		},
	}
	ConsumerAMFCreateUEContextRequsetTable[CreateUEContext201] = models.CreateUEContextRequestBody{
		JsonData: &models.Amf_Comm_UeContextCreateData{
			UeContext: &models.Amf_Comm_UeContext{
				Supi: "imsi-208930000007487",
				RestrictedRatList: []models.RatType{
					models.RatType_NR,
				},
			},
			TargetId: &models.Amf_Comm_NgRanTargetId{
				RanNodeId: &models.GlobalRanNodeId{
					PlmnId: &models.PlmnId{
						Mcc: "208",
						Mnc: "93",
					},
					N3IwfId: "123",
					GNbId: &models.GNbId{
						BitLength: 123,
						GNBValue:  "string",
					},
					NgeNbId: "string",
				},
				Tai: &models.Tai{
					PlmnId: &models.PlmnId{
						Mcc: "208",
						Mnc: "93",
					},
					Tac: "000001",
				},
			},
			SourceToTargetData: &models.Amf_Comm_N2InfoContent{
				NgapMessageType: 0,
				NgapIeType:      "NgapIeType_PDU_RES_SETUP_REQ",
				NgapData: &models.RefToBinaryData{
					ContentId: "N2SmInfo",
				},
			},
			PduSessionList: []models.Amf_Comm_N2SmInformation{
				{
					PduSessionId: 10,
					N2InfoContent: &models.Amf_Comm_N2InfoContent{
						NgapIeType: models.Amf_Comm_NgapIeType_PDU_RES_REL_CMD,
						NgapData: &models.RefToBinaryData{
							ContentId: "N2SmInfo",
						},
					},
				},
			},
			N2NotifyUri:       "127.0.0.1",
			UeRadioCapability: nil,
			NgapCause:         nil,
			SupportedFeatures: "",
		},
	}
}

var ConsumerAMFReleaseUEContextRequestTable = make(map[string]models.Amf_Comm_UEContextRelease)

func init() {
	ConsumerAMFReleaseUEContextRequestTable[UeContextRelease404] = models.Amf_Comm_UEContextRelease{
		Supi:                "",
		UnauthenticatedSupi: false,
		NgapCause: &models.NgApCause{
			Group: 0,
			Value: 0,
		},
	}
	ConsumerAMFReleaseUEContextRequestTable[UeContextRelease201] = models.Amf_Comm_UEContextRelease{
		Supi:                "imsi-208930000007487",
		UnauthenticatedSupi: true,
		NgapCause: &models.NgApCause{
			Group: 0,
			Value: 0,
		},
	}

}

var ConsumerAMFUEContextTransferRequestTable = make(map[string]models.UEContextTransferRequestBody)

func init() {
	ConsumerAMFUEContextTransferRequestTable[UeContextTransfer404] = models.UEContextTransferRequestBody{
		JsonData: &models.Amf_Comm_UeContextTransferReqData{
			Reason:            "",
			AccessType:        "",
			PlmnId:            nil,
			RegRequest:        nil,
			SupportedFeatures: "",
		},
	}
	ConsumerAMFUEContextTransferRequestTable[UeContextTransferINIT_REG200] = models.UEContextTransferRequestBody{
		JsonData: &models.Amf_Comm_UeContextTransferReqData{
			Reason:            models.Amf_Comm_TransferReason_INIT_REG,
			AccessType:        models.AccessType_3_GPP_ACCESS,
			PlmnId:            nil,
			RegRequest:        nil,
			SupportedFeatures: "",
		},
	}
	ConsumerAMFUEContextTransferRequestTable[UeContextTransferMOBI_REG200] = models.UEContextTransferRequestBody{
		JsonData: &models.Amf_Comm_UeContextTransferReqData{
			Reason:            models.Amf_Comm_TransferReason_MOBI_REG,
			AccessType:        models.AccessType_3_GPP_ACCESS,
			PlmnId:            nil,
			RegRequest:        nil,
			SupportedFeatures: "",
		},
	}
}

var ConsumerAMFUEContextEBIAssignmentTable = make(map[string]models.Amf_Comm_AssignEbiData)

func init() {
	ConsumerAMFUEContextEBIAssignmentTable[AssignEbiData403] = models.Amf_Comm_AssignEbiData{
		PduSessionId:    0,
		ArpList:         nil,
		ReleasedEbiList: nil,
	}
	ConsumerAMFUEContextEBIAssignmentTable[AssignEbiData200] = models.Amf_Comm_AssignEbiData{
		PduSessionId:    10,
		ArpList:         nil,
		ReleasedEbiList: nil,
	}
}

var ConsumerRegistrationStatusUpdateTable = make(map[string]models.Amf_Comm_UeRegStatusUpdateReqData)

func init() {
	ConsumerRegistrationStatusUpdateTable[RegistrationStatusUpdate200] = models.Amf_Comm_UeRegStatusUpdateReqData{
		TransferStatus:       models.Amf_Comm_UeContextTransferStatus_TRANSFERRED,
		ToReleaseSessionList: nil,
		PcfReselectedInd:     false,
	}
	ConsumerRegistrationStatusUpdateTable[RegistrationStatusUpdate404] = models.Amf_Comm_UeRegStatusUpdateReqData{
		TransferStatus:       "",
		ToReleaseSessionList: nil,
		PcfReselectedInd:     false,
	}

}
