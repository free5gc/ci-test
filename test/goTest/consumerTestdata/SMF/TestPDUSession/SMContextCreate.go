package TestPDUSession

import (
	"github.com/google/uuid"

	"github.com/free5gc/nas/ie"
	"github.com/free5gc/nas/message"
	"github.com/free5gc/openapi/models"
)

const (
	SERVICE_REQUEST = "Service Request"
	ACTIVATING      = "ACTIVATING"
)

// nasMessagePDUSessionEstablishmentRequestData holds the fixture values used to
// build the N1 SM PDU. Migrated to the new nas API: the IEs are now typed
// structs in nas/ie instead of nasType wrappers carrying raw octets, so the
// placeholder values the old table encoded as octets (IEI in the high nibble,
// value 0) are expressed directly as zero-valued fields.
type nasMessagePDUSessionEstablishmentRequestData struct {
	inPDUSessionID                   uint8
	inPTI                            uint8
	inIntegrityProtectionMaxDataRate *ie.IntegrityProtectionMaxDataRate
	inPDUSessType                    *ie.PDUSessType
	inSSCMode                        *ie.SSCMode
	inCapability5GSM                 *ie.Capability5GSM
	inMaxNumOfSupportedPktFilters    *ie.MaxNumOfSupportedPktFilters
	inAlwaysonPDUSessReq             *ie.AlwaysonPDUSessReq
	inSMPDUDNReqCntr                 *ie.SMPDUDNReqCntr
	inExtendedProtCfgOpts            *ie.ExtendedProtCfgOpts
}

var NasMessagePDUSessionEstablishmentRequestTable = make(map[string]nasMessagePDUSessionEstablishmentRequestData)

func init() {
	NasMessagePDUSessionEstablishmentRequestTable[SERVICE_REQUEST] = nasMessagePDUSessionEstablishmentRequestData{
		inPDUSessionID: 0x01,
		inPTI:          0x01,
		inIntegrityProtectionMaxDataRate: &ie.IntegrityProtectionMaxDataRate{
			Uplink:   0x01,
			Downlink: 0x01,
		},
		// The old fixture set these IEs to their IEI with a zero value.
		inPDUSessType:                 &ie.PDUSessType{},
		inSSCMode:                     &ie.SSCMode{},
		inCapability5GSM:              &ie.Capability5GSM{Rqos: true},
		inMaxNumOfSupportedPktFilters: &ie.MaxNumOfSupportedPktFilters{MaxNumOfSupportedPktFilters: 0x01},
		inAlwaysonPDUSessReq:          &ie.AlwaysonPDUSessReq{},
		inSMPDUDNReqCntr:              &ie.SMPDUDNReqCntr{DNSpecificId: 0x01},
		inExtendedProtCfgOpts: &ie.ExtendedProtCfgOpts{
			FromMs: &ie.ExtCfgOptFromMs{},
		},
	}
}

func GetEstablishmentRequestData(testType string) (n1SmBytes []byte) {
	table := NasMessagePDUSessionEstablishmentRequestTable[testType]

	m := &message.PDUSessEstReq{
		PDUSessId:                      table.inPDUSessionID,
		PTI:                            table.inPTI,
		IntegrityProtectionMaxDataRate: table.inIntegrityProtectionMaxDataRate,
		PDUSessType:                    table.inPDUSessType,
		SSCMode:                        table.inSSCMode,
		Capability5GSM:                 table.inCapability5GSM,
		MaxNumOfSupportedPktFilters:    table.inMaxNumOfSupportedPktFilters,
		AlwaysonPDUSessReq:             table.inAlwaysonPDUSessReq,
		SMPDUDNReqCntr:                 table.inSMPDUDNReqCntr,
		ExtendedProtCfgOpts:            table.inExtendedProtCfgOpts,
	}

	n1SmBytes, err := m.MarshalBinary()
	if err != nil {
		return nil
	}
	return n1SmBytes
}

var ConsumerSMFPDUSessionSMContextCreateTable = make(map[string]models.Smf_PDUSess_SmContextCreateData)

func init() {
	ConsumerSMFPDUSessionSMContextCreateTable[SERVICE_REQUEST] = models.Smf_PDUSess_SmContextCreateData{
		Supi:                "imsi-208930000007487",
		UnauthenticatedSupi: false,
		PduSessionId:        2,
		Dnn:                 "internet",
		ServingNfId:         uuid.New().String(),
		Guami: &models.Guami{
			PlmnId: &models.PlmnIdNid{
				Mcc: "208",
				Mnc: "93",
			},
			AmfId: "cafe00",
		},
		ServingNetwork: &models.PlmnIdNid{
			Mcc: "208",
			Mnc: "93",
		},
		RequestType: models.Smf_PDUSess_RequestType_INITIAL_REQUEST,
		N1SmMsg: &models.RefToBinaryData{
			ContentId: "NGAP",
		},
		AnType:  models.AccessType_3_GPP_ACCESS,
		RatType: models.RatType_NR,
		SelMode: models.Smf_PDUSess_DnnSelectionMode_VERIFIED,
	}
}

// nasMessageULNASTransportData holds the fixture values for the UL NAS
// transport envelope. In the new API the message type and EPD come from the
// message struct itself, so only the IEs remain configurable here.
type nasMessageULNASTransportData struct {
	inPayloadCntr *ie.PayloadCntr
	inPDUSessID   *ie.PDUSessId2
	inReqType     *ie.ReqType
	inSNSSAI      *ie.SNSSAI
}

var NasMessageNasMessageULNASTransportDataTable = make(map[string]nasMessageULNASTransportData)

func init() {
	NasMessageNasMessageULNASTransportDataTable[SERVICE_REQUEST] = nasMessageULNASTransportData{
		inPayloadCntr: &ie.PayloadCntr{
			Pct:      ie.PayloadCntrType_N1SMInfo,
			Contents: GetEstablishmentRequestData(SERVICE_REQUEST),
		},
		inPDUSessID: &ie.PDUSessId2{Value: 10},
		inReqType:   &ie.ReqType{Value: ie.ReqType_InitialReq},
		// The old fixture packed SST 0x01 and SD 0x020301 into a raw octet
		// array; SD is a hex string in the new API.
		inSNSSAI: &ie.SNSSAI{SST: 0x01, SD: "020301"},
	}
}

func GetUlNasTransportData(testType string) *message.ULNASTransport {
	table := NasMessageNasMessageULNASTransportDataTable[testType]

	return &message.ULNASTransport{
		PayloadCntrType: &ie.PayloadCntrType{Value: ie.PayloadCntrType_N1SMInfo},
		PayloadCntr:     table.inPayloadCntr,
		PDUSessID:       table.inPDUSessID,
		ReqType:         table.inReqType,
		SNSSAI:          table.inSNSSAI,
	}
}

var ConsumerSMFPDUSessionUpdateContextTable = make(map[string]models.UpdateSmContextRequestBody)

func init() {
	ConsumerSMFPDUSessionUpdateContextTable[ACTIVATING] = models.UpdateSmContextRequestBody{
		JsonData: &models.Smf_PDUSess_SmContextUpdateData{
			UpCnxState:  ACTIVATING,
			ServingNfId: uuid.New().String(),
			Guami: &models.Guami{
				PlmnId: &models.PlmnIdNid{
					Mcc: "208",
					Mnc: "93",
				},
				AmfId: "cafe00",
			},
			ServingNetwork: &models.PlmnIdNid{
				Mcc: "208",
				Mnc: "93",
			},
			N1SmMsg: &models.RefToBinaryData{
				ContentId: "NGAP",
			},
			AnType:  models.AccessType_3_GPP_ACCESS,
			RatType: models.RatType_NR,
		},
		BinaryDataN1SmMessage:     nil,
		BinaryDataN2SmInformation: nil,
	}
}
