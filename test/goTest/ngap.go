package test

import (
	"encoding/hex"

	"github.com/calee0219/fatal"
	"github.com/free5gc/aper"
	"github.com/free5gc/ngap"
	"github.com/free5gc/ngap/ngapConvert"
	"github.com/free5gc/ngap/ngapType"
)

var (
	PLMN = ngapType.PLMNIdentity{
		Value: aper.OctetString(PLMN_OCT),
	}
)

func buildNGSetupRequest() (pdu ngapType.NGAPPDU) {

	pdu.Present = ngapType.NGAPPDUPresentInitiatingMessage
	pdu.InitiatingMessage = new(ngapType.InitiatingMessage)

	initiatingMessage := pdu.InitiatingMessage
	initiatingMessage.ProcedureCode.Value = ngapType.ProcedureCodeNGSetup
	initiatingMessage.Criticality.Value = ngapType.CriticalityPresentReject

	initiatingMessage.Value.Present = ngapType.InitiatingMessagePresentNGSetupRequest
	initiatingMessage.Value.NGSetupRequest = new(ngapType.NGSetupRequest)

	nGSetupRequest := initiatingMessage.Value.NGSetupRequest
	nGSetupRequestIEs := &nGSetupRequest.ProtocolIEs

	// GlobalRANNodeID
	ie := ngapType.NGSetupRequestIEs{}
	ie.Id.Value = ngapType.ProtocolIEIDGlobalRANNodeID
	ie.Criticality.Value = ngapType.CriticalityPresentReject
	ie.Value.Present = ngapType.NGSetupRequestIEsPresentGlobalRANNodeID
	ie.Value.GlobalRANNodeID = new(ngapType.GlobalRANNodeID)

	globalRANNodeID := ie.Value.GlobalRANNodeID
	globalRANNodeID.Present = ngapType.GlobalRANNodeIDPresentGlobalGNBID
	globalRANNodeID.GlobalGNBID = new(ngapType.GlobalGNBID)

	globalGNBID := globalRANNodeID.GlobalGNBID
	globalGNBID.PLMNIdentity.Value = aper.OctetString(PLMN_OCT)
	globalGNBID.GNBID.Present = ngapType.GNBIDPresentGNBID
	globalGNBID.GNBID.GNBID = new(aper.BitString)

	gNBID := globalGNBID.GNBID.GNBID

	*gNBID = aper.BitString{
		Bytes:     aper.OctetString(IT_GNB_ID),
		BitLength: 24,
	}
	nGSetupRequestIEs.List = append(nGSetupRequestIEs.List, ie)

	// RANNodeName
	ie = ngapType.NGSetupRequestIEs{}
	ie.Id.Value = ngapType.ProtocolIEIDRANNodeName
	ie.Criticality.Value = ngapType.CriticalityPresentIgnore
	ie.Value.Present = ngapType.NGSetupRequestIEsPresentRANNodeName
	ie.Value.RANNodeName = new(ngapType.RANNodeName)

	rANNodeName := ie.Value.RANNodeName
	rANNodeName.Value = "free5GC"
	nGSetupRequestIEs.List = append(nGSetupRequestIEs.List, ie)
	// SupportedTAList
	ie = ngapType.NGSetupRequestIEs{}
	ie.Id.Value = ngapType.ProtocolIEIDSupportedTAList
	ie.Criticality.Value = ngapType.CriticalityPresentReject
	ie.Value.Present = ngapType.NGSetupRequestIEsPresentSupportedTAList
	ie.Value.SupportedTAList = new(ngapType.SupportedTAList)

	supportedTAList := ie.Value.SupportedTAList

	// SupportedTAItem in SupportedTAList
	supportedTAItem := ngapType.SupportedTAItem{}
	supportedTAItem.TAC.Value = aper.OctetString("\x00\x00\x01")

	broadcastPLMNList := &supportedTAItem.BroadcastPLMNList
	// BroadcastPLMNItem in BroadcastPLMNList
	broadcastPLMNItem := ngapType.BroadcastPLMNItem{}
	broadcastPLMNItem.PLMNIdentity.Value = aper.OctetString(PLMN_OCT)

	sliceSupportList := &broadcastPLMNItem.TAISliceSupportList
	// SliceSupportItem in SliceSupportList
	sliceSupportItem := ngapType.SliceSupportItem{}
	sliceSupportItem.SNSSAI.SST.Value = aper.OctetString(SST_OCT)
	// optional
	sliceSupportItem.SNSSAI.SD = new(ngapType.SD)
	sliceSupportItem.SNSSAI.SD.Value = aper.OctetString(SD_OCT)

	sliceSupportList.List = append(sliceSupportList.List, sliceSupportItem)

	broadcastPLMNList.List = append(broadcastPLMNList.List, broadcastPLMNItem)

	supportedTAList.List = append(supportedTAList.List, supportedTAItem)

	nGSetupRequestIEs.List = append(nGSetupRequestIEs.List, ie)

	// PagingDRX
	ie = ngapType.NGSetupRequestIEs{}
	ie.Id.Value = ngapType.ProtocolIEIDDefaultPagingDRX
	ie.Criticality.Value = ngapType.CriticalityPresentIgnore
	ie.Value.Present = ngapType.NGSetupRequestIEsPresentDefaultPagingDRX
	ie.Value.DefaultPagingDRX = new(ngapType.PagingDRX)

	pagingDRX := ie.Value.DefaultPagingDRX
	pagingDRX.Value = ngapType.PagingDRXPresentV128
	nGSetupRequestIEs.List = append(nGSetupRequestIEs.List, ie)

	return pdu
}

func GetNGSetupRequest(gnbId []byte, bitlength uint64, name string) ([]byte, error) {
	message := buildNGSetupRequest()
	// GlobalRANNodeID
	ie := message.InitiatingMessage.Value.NGSetupRequest.ProtocolIEs.List[0]
	gnbID := ie.Value.GlobalRANNodeID.GlobalGNBID.GNBID.GNBID
	gnbID.Bytes = gnbId
	gnbID.BitLength = bitlength
	// RANNodeName
	ie = message.InitiatingMessage.Value.NGSetupRequest.ProtocolIEs.List[1]
	ie.Value.RANNodeName.Value = name

	return ngap.Encoder(message)
}

func buildInitialUEMessage(ranUeNgapID int64, nasPdu []byte, fiveGSTmsi string) (pdu ngapType.NGAPPDU) {

	pdu.Present = ngapType.NGAPPDUPresentInitiatingMessage
	pdu.InitiatingMessage = new(ngapType.InitiatingMessage)

	initiatingMessage := pdu.InitiatingMessage
	initiatingMessage.ProcedureCode.Value = ngapType.ProcedureCodeInitialUEMessage
	initiatingMessage.Criticality.Value = ngapType.CriticalityPresentIgnore

	initiatingMessage.Value.Present = ngapType.InitiatingMessagePresentInitialUEMessage
	initiatingMessage.Value.InitialUEMessage = new(ngapType.InitialUEMessage)

	initialUEMessage := initiatingMessage.Value.InitialUEMessage
	initialUEMessageIEs := &initialUEMessage.ProtocolIEs

	// RAN UE NGAP ID
	ie := ngapType.InitialUEMessageIEs{}
	ie.Id.Value = ngapType.ProtocolIEIDRANUENGAPID
	ie.Criticality.Value = ngapType.CriticalityPresentReject
	ie.Value.Present = ngapType.InitialUEMessageIEsPresentRANUENGAPID
	ie.Value.RANUENGAPID = new(ngapType.RANUENGAPID)

	rANUENGAPID := ie.Value.RANUENGAPID
	rANUENGAPID.Value = ranUeNgapID

	initialUEMessageIEs.List = append(initialUEMessageIEs.List, ie)

	// NAS-PDU
	ie = ngapType.InitialUEMessageIEs{}
	ie.Id.Value = ngapType.ProtocolIEIDNASPDU
	ie.Criticality.Value = ngapType.CriticalityPresentReject
	ie.Value.Present = ngapType.InitialUEMessageIEsPresentNASPDU
	ie.Value.NASPDU = new(ngapType.NASPDU)

	// TODO: complete NAS-PDU
	nASPDU := ie.Value.NASPDU
	nASPDU.Value = nasPdu

	initialUEMessageIEs.List = append(initialUEMessageIEs.List, ie)

	// User Location Information
	ie = ngapType.InitialUEMessageIEs{}
	ie.Id.Value = ngapType.ProtocolIEIDUserLocationInformation
	ie.Criticality.Value = ngapType.CriticalityPresentReject
	ie.Value.Present = ngapType.InitialUEMessageIEsPresentUserLocationInformation
	ie.Value.UserLocationInformation = new(ngapType.UserLocationInformation)

	userLocationInformation := ie.Value.UserLocationInformation
	userLocationInformation.Present = ngapType.UserLocationInformationPresentUserLocationInformationNR
	userLocationInformation.UserLocationInformationNR = new(ngapType.UserLocationInformationNR)

	userLocationInformationNR := userLocationInformation.UserLocationInformationNR
	userLocationInformationNR.NRCGI.PLMNIdentity.Value = aper.OctetString(PLMN_OCT)
	userLocationInformationNR.NRCGI.NRCellIdentity.Value = aper.BitString{
		Bytes:     []byte{0x00, 0x00, 0x00, 0x00, 0x10},
		BitLength: 36,
	}

	userLocationInformationNR.TAI.PLMNIdentity.Value = aper.OctetString(PLMN_OCT)
	userLocationInformationNR.TAI.TAC.Value = aper.OctetString("\x00\x00\x01")

	initialUEMessageIEs.List = append(initialUEMessageIEs.List, ie)

	// RRC Establishment Cause
	ie = ngapType.InitialUEMessageIEs{}
	ie.Id.Value = ngapType.ProtocolIEIDRRCEstablishmentCause
	ie.Criticality.Value = ngapType.CriticalityPresentIgnore
	ie.Value.Present = ngapType.InitialUEMessageIEsPresentRRCEstablishmentCause
	ie.Value.RRCEstablishmentCause = new(ngapType.RRCEstablishmentCause)

	rRCEstablishmentCause := ie.Value.RRCEstablishmentCause
	rRCEstablishmentCause.Value = ngapType.RRCEstablishmentCausePresentMtAccess

	initialUEMessageIEs.List = append(initialUEMessageIEs.List, ie)

	// 5G-S-TSMI (optional)
	if fiveGSTmsi != "" {
		ie = ngapType.InitialUEMessageIEs{}
		ie.Id.Value = ngapType.ProtocolIEIDFiveGSTMSI
		ie.Criticality.Value = ngapType.CriticalityPresentReject
		ie.Value.Present = ngapType.InitialUEMessageIEsPresentFiveGSTMSI
		ie.Value.FiveGSTMSI = new(ngapType.FiveGSTMSI)

		fiveGSTMSI := ie.Value.FiveGSTMSI
		amfSetID, err := hex.DecodeString(fiveGSTmsi[:4])
		if err != nil {
			fatal.Fatalf("DecodeString error in BuildInitialUEMessage: %+v", err)
		}
		fiveGSTMSI.AMFSetID.Value = aper.BitString{
			Bytes:     amfSetID,
			BitLength: 10,
		}
		amfPointer, err := hex.DecodeString(fiveGSTmsi[2:4])
		if err != nil {
			fatal.Fatalf("DecodeString error in BuildInitialUEMessage: %+v", err)
		}
		fiveGSTMSI.AMFPointer.Value = aper.BitString{
			Bytes:     amfPointer,
			BitLength: 6,
		}
		tmsi, err := hex.DecodeString(fiveGSTmsi[4:])
		if err != nil {
			fatal.Fatalf("DecodeString error in BuildInitialUEMessage: %+v", err)
		}
		fiveGSTMSI.FiveGTMSI.Value = aper.OctetString(tmsi)

		initialUEMessageIEs.List = append(initialUEMessageIEs.List, ie)
	}
	// AMF Set ID (optional)

	// UE Context Request (optional)
	ie = ngapType.InitialUEMessageIEs{}
	ie.Id.Value = ngapType.ProtocolIEIDUEContextRequest
	ie.Criticality.Value = ngapType.CriticalityPresentIgnore
	ie.Value.Present = ngapType.InitialUEMessageIEsPresentUEContextRequest
	ie.Value.UEContextRequest = new(ngapType.UEContextRequest)
	ie.Value.UEContextRequest.Value = ngapType.UEContextRequestPresentRequested
	initialUEMessageIEs.List = append(initialUEMessageIEs.List, ie)

	// Allowed NSSAI (optional)
	return pdu
}

func GetInitialUEMessage(ranUeNgapID int64, nasPdu []byte, fiveGSTmsi string) ([]byte, error) {
	message := buildInitialUEMessage(ranUeNgapID, nasPdu, fiveGSTmsi)
	return ngap.Encoder(message)
}

func buildUplinkNasTransport(amfUeNgapID, ranUeNgapID int64, nasPdu []byte) (pdu ngapType.NGAPPDU) {

	pdu.Present = ngapType.NGAPPDUPresentInitiatingMessage
	pdu.InitiatingMessage = new(ngapType.InitiatingMessage)

	initiatingMessage := pdu.InitiatingMessage
	initiatingMessage.ProcedureCode.Value = ngapType.ProcedureCodeUplinkNASTransport
	initiatingMessage.Criticality.Value = ngapType.CriticalityPresentIgnore

	initiatingMessage.Value.Present = ngapType.InitiatingMessagePresentUplinkNASTransport
	initiatingMessage.Value.UplinkNASTransport = new(ngapType.UplinkNASTransport)

	uplinkNasTransport := initiatingMessage.Value.UplinkNASTransport
	uplinkNasTransportIEs := &uplinkNasTransport.ProtocolIEs

	// AMF UE NGAP ID
	ie := ngapType.UplinkNASTransportIEs{}
	ie.Id.Value = ngapType.ProtocolIEIDAMFUENGAPID
	ie.Criticality.Value = ngapType.CriticalityPresentReject
	ie.Value.Present = ngapType.UplinkNASTransportIEsPresentAMFUENGAPID
	ie.Value.AMFUENGAPID = new(ngapType.AMFUENGAPID)

	aMFUENGAPID := ie.Value.AMFUENGAPID
	aMFUENGAPID.Value = amfUeNgapID

	uplinkNasTransportIEs.List = append(uplinkNasTransportIEs.List, ie)

	// RAN UE NGAP ID
	ie = ngapType.UplinkNASTransportIEs{}
	ie.Id.Value = ngapType.ProtocolIEIDRANUENGAPID
	ie.Criticality.Value = ngapType.CriticalityPresentReject
	ie.Value.Present = ngapType.UplinkNASTransportIEsPresentRANUENGAPID
	ie.Value.RANUENGAPID = new(ngapType.RANUENGAPID)

	rANUENGAPID := ie.Value.RANUENGAPID
	rANUENGAPID.Value = ranUeNgapID

	uplinkNasTransportIEs.List = append(uplinkNasTransportIEs.List, ie)

	// NAS-PDU
	ie = ngapType.UplinkNASTransportIEs{}
	ie.Id.Value = ngapType.ProtocolIEIDNASPDU
	ie.Criticality.Value = ngapType.CriticalityPresentReject
	ie.Value.Present = ngapType.UplinkNASTransportIEsPresentNASPDU
	ie.Value.NASPDU = new(ngapType.NASPDU)

	// TODO: complete NAS-PDU
	nASPDU := ie.Value.NASPDU
	nASPDU.Value = nasPdu

	uplinkNasTransportIEs.List = append(uplinkNasTransportIEs.List, ie)

	// User Location Information
	ie = ngapType.UplinkNASTransportIEs{}
	ie.Id.Value = ngapType.ProtocolIEIDUserLocationInformation
	ie.Criticality.Value = ngapType.CriticalityPresentIgnore
	ie.Value.Present = ngapType.UplinkNASTransportIEsPresentUserLocationInformation
	ie.Value.UserLocationInformation = new(ngapType.UserLocationInformation)

	userLocationInformation := ie.Value.UserLocationInformation
	userLocationInformation.Present = ngapType.UserLocationInformationPresentUserLocationInformationNR
	userLocationInformation.UserLocationInformationNR = new(ngapType.UserLocationInformationNR)

	userLocationInformationNR := userLocationInformation.UserLocationInformationNR
	userLocationInformationNR.NRCGI.PLMNIdentity.Value = aper.OctetString(PLMN_OCT)
	userLocationInformationNR.NRCGI.NRCellIdentity.Value = aper.BitString{
		Bytes:     []byte{0x00, 0x00, 0x00, 0x00, 0x10},
		BitLength: 36,
	}

	userLocationInformationNR.TAI.PLMNIdentity.Value = aper.OctetString(PLMN_OCT)
	userLocationInformationNR.TAI.TAC.Value = aper.OctetString("\x00\x00\x01")

	uplinkNasTransportIEs.List = append(uplinkNasTransportIEs.List, ie)

	return pdu
}

func GetUplinkNASTransport(amfUeNgapID, ranUeNgapID int64, nasPdu []byte) ([]byte, error) {
	message := buildUplinkNasTransport(amfUeNgapID, ranUeNgapID, nasPdu)
	return ngap.Encoder(message)
}

func buildInitialContextSetupResponseForRegistraionTest(amfUeNgapID, ranUeNgapID int64) (pdu ngapType.NGAPPDU) {

	pdu.Present = ngapType.NGAPPDUPresentSuccessfulOutcome
	pdu.SuccessfulOutcome = new(ngapType.SuccessfulOutcome)

	successfulOutcome := pdu.SuccessfulOutcome
	successfulOutcome.ProcedureCode.Value = ngapType.ProcedureCodeInitialContextSetup
	successfulOutcome.Criticality.Value = ngapType.CriticalityPresentReject

	successfulOutcome.Value.Present = ngapType.SuccessfulOutcomePresentInitialContextSetupResponse
	successfulOutcome.Value.InitialContextSetupResponse = new(ngapType.InitialContextSetupResponse)

	initialContextSetupResponse := successfulOutcome.Value.InitialContextSetupResponse
	initialContextSetupResponseIEs := &initialContextSetupResponse.ProtocolIEs

	// AMF UE NGAP ID
	ie := ngapType.InitialContextSetupResponseIEs{}
	ie.Id.Value = ngapType.ProtocolIEIDAMFUENGAPID
	ie.Criticality.Value = ngapType.CriticalityPresentIgnore
	ie.Value.Present = ngapType.InitialContextSetupResponseIEsPresentAMFUENGAPID
	ie.Value.AMFUENGAPID = new(ngapType.AMFUENGAPID)

	aMFUENGAPID := ie.Value.AMFUENGAPID
	aMFUENGAPID.Value = amfUeNgapID

	initialContextSetupResponseIEs.List = append(initialContextSetupResponseIEs.List, ie)

	// RAN UE NGAP ID
	ie = ngapType.InitialContextSetupResponseIEs{}
	ie.Id.Value = ngapType.ProtocolIEIDRANUENGAPID
	ie.Criticality.Value = ngapType.CriticalityPresentIgnore
	ie.Value.Present = ngapType.InitialContextSetupResponseIEsPresentRANUENGAPID
	ie.Value.RANUENGAPID = new(ngapType.RANUENGAPID)

	rANUENGAPID := ie.Value.RANUENGAPID
	rANUENGAPID.Value = ranUeNgapID

	initialContextSetupResponseIEs.List = append(initialContextSetupResponseIEs.List, ie)

	return pdu
}

func GetInitialContextSetupResponse(amfUeNgapID int64, ranUeNgapID int64) ([]byte, error) {
	message := buildInitialContextSetupResponseForRegistraionTest(amfUeNgapID, ranUeNgapID)

	return ngap.Encoder(message)
}

func buildPDUSessionResourceSetupResponseTransfer(ipv4 string) (data ngapType.PDUSessionResourceSetupResponseTransfer) {
	// QoS Flow per TNL Information
	qosFlowPerTNLInformation := &data.DLQosFlowPerTNLInformation
	qosFlowPerTNLInformation.UPTransportLayerInformation.Present = ngapType.UPTransportLayerInformationPresentGTPTunnel

	// UP Transport Layer Information in QoS Flow per TNL Information
	upTransportLayerInformation := &qosFlowPerTNLInformation.UPTransportLayerInformation
	upTransportLayerInformation.Present = ngapType.UPTransportLayerInformationPresentGTPTunnel
	upTransportLayerInformation.GTPTunnel = new(ngapType.GTPTunnel)
	upTransportLayerInformation.GTPTunnel.GTPTEID.Value = aper.OctetString("\x00\x00\x00\x01")
	upTransportLayerInformation.GTPTunnel.TransportLayerAddress = ngapConvert.IPAddressToNgap(ipv4, "")

	// Associated QoS Flow List in QoS Flow per TNL Information
	associatedQosFlowList := &qosFlowPerTNLInformation.AssociatedQosFlowList

	associatedQosFlowItem := ngapType.AssociatedQosFlowItem{}
	associatedQosFlowItem.QosFlowIdentifier.Value = 1
	associatedQosFlowList.List = append(associatedQosFlowList.List, associatedQosFlowItem)

	return data
}

func GetPDUSessionResourceSetupResponseTransfer(ipv4 string) []byte {
	data := buildPDUSessionResourceSetupResponseTransfer(ipv4)
	encodeData, err := aper.MarshalWithParams(data, "valueExt")
	if err != nil {
		fatal.Fatalf("aper MarshalWithParams error in GetPDUSessionResourceSetupResponseTransfer: %+v", err)
	}
	return encodeData
}

func buildPDUSessionResourceSetupResponseForRegistrationTest(
	pduSessionId int64, amfUeNgapID, ranUeNgapID int64, ipv4 string) (pdu ngapType.NGAPPDU) {

	pdu.Present = ngapType.NGAPPDUPresentSuccessfulOutcome
	pdu.SuccessfulOutcome = new(ngapType.SuccessfulOutcome)

	successfulOutcome := pdu.SuccessfulOutcome
	successfulOutcome.ProcedureCode.Value = ngapType.ProcedureCodePDUSessionResourceSetup
	successfulOutcome.Criticality.Value = ngapType.CriticalityPresentReject

	successfulOutcome.Value.Present = ngapType.SuccessfulOutcomePresentPDUSessionResourceSetupResponse
	successfulOutcome.Value.PDUSessionResourceSetupResponse = new(ngapType.PDUSessionResourceSetupResponse)

	pDUSessionResourceSetupResponse := successfulOutcome.Value.PDUSessionResourceSetupResponse
	pDUSessionResourceSetupResponseIEs := &pDUSessionResourceSetupResponse.ProtocolIEs

	// AMF UE NGAP ID
	ie := ngapType.PDUSessionResourceSetupResponseIEs{}
	ie.Id.Value = ngapType.ProtocolIEIDAMFUENGAPID
	ie.Criticality.Value = ngapType.CriticalityPresentIgnore
	ie.Value.Present = ngapType.PDUSessionResourceSetupResponseIEsPresentAMFUENGAPID
	ie.Value.AMFUENGAPID = new(ngapType.AMFUENGAPID)

	aMFUENGAPID := ie.Value.AMFUENGAPID
	aMFUENGAPID.Value = amfUeNgapID

	pDUSessionResourceSetupResponseIEs.List = append(pDUSessionResourceSetupResponseIEs.List, ie)

	// RAN UE NGAP ID
	ie = ngapType.PDUSessionResourceSetupResponseIEs{}
	ie.Id.Value = ngapType.ProtocolIEIDRANUENGAPID
	ie.Criticality.Value = ngapType.CriticalityPresentIgnore
	ie.Value.Present = ngapType.PDUSessionResourceSetupResponseIEsPresentRANUENGAPID
	ie.Value.RANUENGAPID = new(ngapType.RANUENGAPID)

	rANUENGAPID := ie.Value.RANUENGAPID
	rANUENGAPID.Value = ranUeNgapID

	pDUSessionResourceSetupResponseIEs.List = append(pDUSessionResourceSetupResponseIEs.List, ie)

	// PDU Session Resource Setup Response List
	ie = ngapType.PDUSessionResourceSetupResponseIEs{}
	ie.Id.Value = ngapType.ProtocolIEIDPDUSessionResourceSetupListSURes
	ie.Criticality.Value = ngapType.CriticalityPresentIgnore
	ie.Value.Present = ngapType.PDUSessionResourceSetupResponseIEsPresentPDUSessionResourceSetupListSURes
	ie.Value.PDUSessionResourceSetupListSURes = new(ngapType.PDUSessionResourceSetupListSURes)

	pDUSessionResourceSetupListSURes := ie.Value.PDUSessionResourceSetupListSURes

	// PDU Session Resource Setup Response Item in PDU Session Resource Setup Response List
	pDUSessionResourceSetupItemSURes := ngapType.PDUSessionResourceSetupItemSURes{}
	pDUSessionResourceSetupItemSURes.PDUSessionID.Value = pduSessionId

	pDUSessionResourceSetupItemSURes.PDUSessionResourceSetupResponseTransfer =
		GetPDUSessionResourceSetupResponseTransfer(ipv4)

	pDUSessionResourceSetupListSURes.List = append(pDUSessionResourceSetupListSURes.List, pDUSessionResourceSetupItemSURes)

	pDUSessionResourceSetupResponseIEs.List = append(pDUSessionResourceSetupResponseIEs.List, ie)

	// PDU Sessuin Resource Failed to Setup List
	// ie = ngapType.PDUSessionResourceSetupResponseIEs{}
	// ie.Id.Value = ngapType.ProtocolIEIDPDUSessionResourceFailedToSetupListSURes
	// ie.Criticality.Value = ngapType.CriticalityPresentIgnore
	// ie.Value.Present = ngapType.PDUSessionResourceSetupResponseIEsPresentPDUSessionResourceFailedToSetupListSURes
	// ie.Value.PDUSessionResourceFailedToSetupListSURes = new(ngapType.PDUSessionResourceFailedToSetupListSURes)

	// pDUSessionResourceFailedToSetupListSURes := ie.Value.PDUSessionResourceFailedToSetupListSURes

	// // PDU Session Resource Failed to Setup Item in PDU Sessuin Resource Failed to Setup List
	// pDUSessionResourceFailedToSetupItemSURes := ngapType.PDUSessionResourceFailedToSetupItemSURes{}
	// pDUSessionResourceFailedToSetupItemSURes.PDUSessionID.Value = 10
	// pDUSessionResourceFailedToSetupItemSURes.PDUSessionResourceSetupUnsuccessfulTransfer =
	// 	GetPDUSessionResourceSetupUnsucessfulTransfer()

	// pDUSessionResourceFailedToSetupListSURes.List =
	// 	append(pDUSessionResourceFailedToSetupListSURes.List, pDUSessionResourceFailedToSetupItemSURes)

	// pDUSessionResourceSetupResponseIEs.List = append(pDUSessionResourceSetupResponseIEs.List, ie)
	// Criticality Diagnostics (optional)
	return pdu
}

func GetPDUSessionResourceSetupResponse(pduSessionId int64, amfUeNgapID int64, ranUeNgapID int64, ipv4 string) ([]byte, error) {
	message := buildPDUSessionResourceSetupResponseForRegistrationTest(pduSessionId, amfUeNgapID, ranUeNgapID, ipv4)
	return ngap.Encoder(message)
}

func buildUEContextReleaseComplete(amfUeNgapID, ranUeNgapID int64, pduSessionIDList []int64) (pdu ngapType.NGAPPDU) {
	pdu.Present = ngapType.NGAPPDUPresentSuccessfulOutcome
	pdu.SuccessfulOutcome = new(ngapType.SuccessfulOutcome)

	successfulOutcome := pdu.SuccessfulOutcome
	successfulOutcome.ProcedureCode.Value = ngapType.ProcedureCodeUEContextRelease
	successfulOutcome.Criticality.Value = ngapType.CriticalityPresentReject

	successfulOutcome.Value.Present = ngapType.SuccessfulOutcomePresentUEContextReleaseComplete
	successfulOutcome.Value.UEContextReleaseComplete = new(ngapType.UEContextReleaseComplete)

	uEContextReleaseComplete := successfulOutcome.Value.UEContextReleaseComplete
	uEContextReleaseCompleteIEs := &uEContextReleaseComplete.ProtocolIEs

	// AMF UE NGAP ID
	ie := ngapType.UEContextReleaseCompleteIEs{}
	ie.Id.Value = ngapType.ProtocolIEIDAMFUENGAPID
	ie.Criticality.Value = ngapType.CriticalityPresentIgnore
	ie.Value.Present = ngapType.UEContextReleaseCompleteIEsPresentAMFUENGAPID
	ie.Value.AMFUENGAPID = new(ngapType.AMFUENGAPID)

	aMFUENGAPID := ie.Value.AMFUENGAPID
	aMFUENGAPID.Value = amfUeNgapID

	uEContextReleaseCompleteIEs.List = append(uEContextReleaseCompleteIEs.List, ie)

	// RAN UE NGAP ID
	ie = ngapType.UEContextReleaseCompleteIEs{}
	ie.Id.Value = ngapType.ProtocolIEIDRANUENGAPID
	ie.Criticality.Value = ngapType.CriticalityPresentIgnore
	ie.Value.Present = ngapType.UEContextReleaseCompleteIEsPresentRANUENGAPID
	ie.Value.RANUENGAPID = new(ngapType.RANUENGAPID)

	rANUENGAPID := ie.Value.RANUENGAPID
	rANUENGAPID.Value = ranUeNgapID

	uEContextReleaseCompleteIEs.List = append(uEContextReleaseCompleteIEs.List, ie)

	// User Location Information (optional)
	ie = ngapType.UEContextReleaseCompleteIEs{}
	ie.Id.Value = ngapType.ProtocolIEIDUserLocationInformation
	ie.Criticality.Value = ngapType.CriticalityPresentIgnore
	ie.Value.Present = ngapType.UEContextReleaseCompleteIEsPresentUserLocationInformation
	ie.Value.UserLocationInformation = new(ngapType.UserLocationInformation)

	userLocationInformation := ie.Value.UserLocationInformation
	userLocationInformation.Present = ngapType.UserLocationInformationPresentUserLocationInformationNR
	userLocationInformation.UserLocationInformationNR = new(ngapType.UserLocationInformationNR)

	userLocationInformationNR := userLocationInformation.UserLocationInformationNR
	userLocationInformationNR.NRCGI.PLMNIdentity.Value = aper.OctetString(PLMN_OCT)
	userLocationInformationNR.NRCGI.NRCellIdentity.Value = aper.BitString{
		Bytes:     []byte{0x00, 0x00, 0x00, 0x00, 0x10},
		BitLength: 36,
	}

	userLocationInformationNR.TAI.PLMNIdentity.Value = aper.OctetString(PLMN_OCT)
	userLocationInformationNR.TAI.TAC.Value = aper.OctetString("\x00\x00\x01")

	uEContextReleaseCompleteIEs.List = append(uEContextReleaseCompleteIEs.List, ie)

	// PDU Session Resource List
	if pduSessionIDList != nil {
		ie = ngapType.UEContextReleaseCompleteIEs{}
		ie.Id.Value = ngapType.ProtocolIEIDPDUSessionResourceListCxtRelCpl
		ie.Criticality.Value = ngapType.CriticalityPresentReject
		ie.Value.Present = ngapType.UEContextReleaseCompleteIEsPresentPDUSessionResourceListCxtRelCpl
		ie.Value.PDUSessionResourceListCxtRelCpl = new(ngapType.PDUSessionResourceListCxtRelCpl)

		pDUSessionResourceListCxtRelCpl := ie.Value.PDUSessionResourceListCxtRelCpl

		for _, pduSessionID := range pduSessionIDList {
			pDUSessionResourceItemCxtRelCpl := ngapType.PDUSessionResourceItemCxtRelCpl{}
			pDUSessionResourceItemCxtRelCpl.PDUSessionID.Value = pduSessionID
			pDUSessionResourceListCxtRelCpl.List = append(pDUSessionResourceListCxtRelCpl.List, pDUSessionResourceItemCxtRelCpl)
		}

		uEContextReleaseCompleteIEs.List = append(uEContextReleaseCompleteIEs.List, ie)
	}

	return pdu
}

func GetUEContextReleaseComplete(amfUeNgapID, ranUeNgapID int64, pduSessionIDList []int64) ([]byte, error) {
	return ngap.Encoder(buildUEContextReleaseComplete(amfUeNgapID, ranUeNgapID, pduSessionIDList))
}

func getPDUSessionResourceReleaseResponseTransfer() []byte {
	var data ngapType.PDUSessionResourceReleaseResponseTransfer
	encodeData, err := aper.MarshalWithParams(data, "valueExt")
	if err != nil {
		fatal.Fatalf("aper MarshalWithParams error in getPDUSessionResourceReleaseResponseTransfer: %+v", err)
	}
	return encodeData
}

func buildPDUSessionResourceReleaseResponse(amfUeNgapID, ranUeNgapID int64) (pdu ngapType.NGAPPDU) {
	pdu.Present = ngapType.NGAPPDUPresentSuccessfulOutcome
	pdu.SuccessfulOutcome = new(ngapType.SuccessfulOutcome)

	successfulOutcome := pdu.SuccessfulOutcome
	successfulOutcome.ProcedureCode.Value = ngapType.ProcedureCodePDUSessionResourceRelease
	successfulOutcome.Criticality.Value = ngapType.CriticalityPresentReject
	successfulOutcome.Value.Present = ngapType.SuccessfulOutcomePresentPDUSessionResourceReleaseResponse
	successfulOutcome.Value.PDUSessionResourceReleaseResponse = new(ngapType.PDUSessionResourceReleaseResponse)

	pDUSessionResourceReleaseResponse := successfulOutcome.Value.PDUSessionResourceReleaseResponse
	pDUSessionResourceReleaseResponseIEs := &pDUSessionResourceReleaseResponse.ProtocolIEs

	// AMF UE NGAP ID
	ie := ngapType.PDUSessionResourceReleaseResponseIEs{}
	ie.Id.Value = ngapType.ProtocolIEIDAMFUENGAPID
	ie.Criticality.Value = ngapType.CriticalityPresentIgnore
	ie.Value.Present = ngapType.PDUSessionResourceReleaseResponseIEsPresentAMFUENGAPID
	ie.Value.AMFUENGAPID = new(ngapType.AMFUENGAPID)
	ie.Value.AMFUENGAPID.Value = amfUeNgapID
	pDUSessionResourceReleaseResponseIEs.List = append(pDUSessionResourceReleaseResponseIEs.List, ie)

	// RAN UE NGAP ID
	ie = ngapType.PDUSessionResourceReleaseResponseIEs{}
	ie.Id.Value = ngapType.ProtocolIEIDRANUENGAPID
	ie.Criticality.Value = ngapType.CriticalityPresentIgnore
	ie.Value.Present = ngapType.PDUSessionResourceReleaseResponseIEsPresentRANUENGAPID
	ie.Value.RANUENGAPID = new(ngapType.RANUENGAPID)
	ie.Value.RANUENGAPID.Value = ranUeNgapID
	pDUSessionResourceReleaseResponseIEs.List = append(pDUSessionResourceReleaseResponseIEs.List, ie)

	// PDU Session Resource Released List
	ie = ngapType.PDUSessionResourceReleaseResponseIEs{}
	ie.Id.Value = ngapType.ProtocolIEIDPDUSessionResourceReleasedListRelRes
	ie.Criticality.Value = ngapType.CriticalityPresentIgnore
	ie.Value.Present = ngapType.PDUSessionResourceReleaseResponseIEsPresentPDUSessionResourceReleasedListRelRes
	ie.Value.PDUSessionResourceReleasedListRelRes = new(ngapType.PDUSessionResourceReleasedListRelRes)

	item := ngapType.PDUSessionResourceReleasedItemRelRes{}
	item.PDUSessionID.Value = 10
	item.PDUSessionResourceReleaseResponseTransfer = getPDUSessionResourceReleaseResponseTransfer()
	ie.Value.PDUSessionResourceReleasedListRelRes.List = append(
		ie.Value.PDUSessionResourceReleasedListRelRes.List, item)
	pDUSessionResourceReleaseResponseIEs.List = append(pDUSessionResourceReleaseResponseIEs.List, ie)

	return pdu
}

func GetPDUSessionResourceReleaseResponse(amfUeNgapID, ranUeNgapID int64) ([]byte, error) {
	return ngap.Encoder(buildPDUSessionResourceReleaseResponse(amfUeNgapID, ranUeNgapID))
}

func buildUEContextReleaseRequest(amfUeNgapID, ranUeNgapID int64, pduSessionIDList []int64) (pdu ngapType.NGAPPDU) {
	pdu.Present = ngapType.NGAPPDUPresentInitiatingMessage
	pdu.InitiatingMessage = new(ngapType.InitiatingMessage)

	initiatingMessage := pdu.InitiatingMessage
	initiatingMessage.ProcedureCode.Value = ngapType.ProcedureCodeUEContextReleaseRequest
	initiatingMessage.Criticality.Value = ngapType.CriticalityPresentIgnore
	initiatingMessage.Value.Present = ngapType.InitiatingMessagePresentUEContextReleaseRequest
	initiatingMessage.Value.UEContextReleaseRequest = new(ngapType.UEContextReleaseRequest)

	uEContextReleaseRequest := initiatingMessage.Value.UEContextReleaseRequest
	uEContextReleaseRequestIEs := &uEContextReleaseRequest.ProtocolIEs

	// AMF UE NGAP ID
	ie := ngapType.UEContextReleaseRequestIEs{}
	ie.Id.Value = ngapType.ProtocolIEIDAMFUENGAPID
	ie.Criticality.Value = ngapType.CriticalityPresentReject
	ie.Value.Present = ngapType.UEContextReleaseRequestIEsPresentAMFUENGAPID
	ie.Value.AMFUENGAPID = new(ngapType.AMFUENGAPID)
	ie.Value.AMFUENGAPID.Value = amfUeNgapID
	uEContextReleaseRequestIEs.List = append(uEContextReleaseRequestIEs.List, ie)

	// RAN UE NGAP ID
	ie = ngapType.UEContextReleaseRequestIEs{}
	ie.Id.Value = ngapType.ProtocolIEIDRANUENGAPID
	ie.Criticality.Value = ngapType.CriticalityPresentReject
	ie.Value.Present = ngapType.UEContextReleaseRequestIEsPresentRANUENGAPID
	ie.Value.RANUENGAPID = new(ngapType.RANUENGAPID)
	ie.Value.RANUENGAPID.Value = ranUeNgapID
	uEContextReleaseRequestIEs.List = append(uEContextReleaseRequestIEs.List, ie)

	// PDU Session Resource List
	if pduSessionIDList != nil {
		ie = ngapType.UEContextReleaseRequestIEs{}
		ie.Id.Value = ngapType.ProtocolIEIDPDUSessionResourceListCxtRelReq
		ie.Criticality.Value = ngapType.CriticalityPresentReject
		ie.Value.Present = ngapType.UEContextReleaseRequestIEsPresentPDUSessionResourceListCxtRelReq
		ie.Value.PDUSessionResourceListCxtRelReq = new(ngapType.PDUSessionResourceListCxtRelReq)
		for _, pduSessionID := range pduSessionIDList {
			item := ngapType.PDUSessionResourceItemCxtRelReq{}
			item.PDUSessionID.Value = pduSessionID
			ie.Value.PDUSessionResourceListCxtRelReq.List = append(ie.Value.PDUSessionResourceListCxtRelReq.List, item)
		}
		uEContextReleaseRequestIEs.List = append(uEContextReleaseRequestIEs.List, ie)
	}

	// Cause
	ie = ngapType.UEContextReleaseRequestIEs{}
	ie.Id.Value = ngapType.ProtocolIEIDCause
	ie.Criticality.Value = ngapType.CriticalityPresentIgnore
	ie.Value.Present = ngapType.UEContextReleaseRequestIEsPresentCause
	ie.Value.Cause = new(ngapType.Cause)
	ie.Value.Cause.Present = ngapType.CausePresentRadioNetwork
	ie.Value.Cause.RadioNetwork = new(ngapType.CauseRadioNetwork)
	ie.Value.Cause.RadioNetwork.Value = ngapType.CauseRadioNetworkPresentTxnrelocoverallExpiry
	uEContextReleaseRequestIEs.List = append(uEContextReleaseRequestIEs.List, ie)

	return pdu
}

func GetUEContextReleaseRequest(amfUeNgapID, ranUeNgapID int64, pduSessionIDList []int64) ([]byte, error) {
	return ngap.Encoder(buildUEContextReleaseRequest(amfUeNgapID, ranUeNgapID, pduSessionIDList))
}

func buildInitialContextSetupResponseForServiceRequest(amfUeNgapID, ranUeNgapID int64, ipv4 string) (pdu ngapType.NGAPPDU) {
	pdu.Present = ngapType.NGAPPDUPresentSuccessfulOutcome
	pdu.SuccessfulOutcome = new(ngapType.SuccessfulOutcome)

	successfulOutcome := pdu.SuccessfulOutcome
	successfulOutcome.ProcedureCode.Value = ngapType.ProcedureCodeInitialContextSetup
	successfulOutcome.Criticality.Value = ngapType.CriticalityPresentReject
	successfulOutcome.Value.Present = ngapType.SuccessfulOutcomePresentInitialContextSetupResponse
	successfulOutcome.Value.InitialContextSetupResponse = new(ngapType.InitialContextSetupResponse)

	initialContextSetupResponse := successfulOutcome.Value.InitialContextSetupResponse
	initialContextSetupResponseIEs := &initialContextSetupResponse.ProtocolIEs

	// AMF UE NGAP ID
	ie := ngapType.InitialContextSetupResponseIEs{}
	ie.Id.Value = ngapType.ProtocolIEIDAMFUENGAPID
	ie.Criticality.Value = ngapType.CriticalityPresentIgnore
	ie.Value.Present = ngapType.InitialContextSetupResponseIEsPresentAMFUENGAPID
	ie.Value.AMFUENGAPID = new(ngapType.AMFUENGAPID)
	ie.Value.AMFUENGAPID.Value = amfUeNgapID
	initialContextSetupResponseIEs.List = append(initialContextSetupResponseIEs.List, ie)

	// RAN UE NGAP ID
	ie = ngapType.InitialContextSetupResponseIEs{}
	ie.Id.Value = ngapType.ProtocolIEIDRANUENGAPID
	ie.Criticality.Value = ngapType.CriticalityPresentIgnore
	ie.Value.Present = ngapType.InitialContextSetupResponseIEsPresentRANUENGAPID
	ie.Value.RANUENGAPID = new(ngapType.RANUENGAPID)
	ie.Value.RANUENGAPID.Value = ranUeNgapID
	initialContextSetupResponseIEs.List = append(initialContextSetupResponseIEs.List, ie)

	// PDU Session Resource Setup Response List
	ie = ngapType.InitialContextSetupResponseIEs{}
	ie.Id.Value = ngapType.ProtocolIEIDPDUSessionResourceSetupListCxtRes
	ie.Criticality.Value = ngapType.CriticalityPresentIgnore
	ie.Value.Present = ngapType.InitialContextSetupResponseIEsPresentPDUSessionResourceSetupListCxtRes
	ie.Value.PDUSessionResourceSetupListCxtRes = new(ngapType.PDUSessionResourceSetupListCxtRes)

	item := ngapType.PDUSessionResourceSetupItemCxtRes{}
	item.PDUSessionID.Value = 10
	item.PDUSessionResourceSetupResponseTransfer = GetPDUSessionResourceSetupResponseTransfer(ipv4)
	ie.Value.PDUSessionResourceSetupListCxtRes.List = append(ie.Value.PDUSessionResourceSetupListCxtRes.List, item)
	initialContextSetupResponseIEs.List = append(initialContextSetupResponseIEs.List, ie)

	return pdu
}

func GetInitialContextSetupResponseForServiceRequest(amfUeNgapID, ranUeNgapID int64, ipv4 string) ([]byte, error) {
	return ngap.Encoder(buildInitialContextSetupResponseForServiceRequest(amfUeNgapID, ranUeNgapID, ipv4))
}

func buildHandoverRequestAcknowledgeTransfer() (data ngapType.HandoverRequestAcknowledgeTransfer) {
	// DL NG-U UP TNL information
	upTransportLayerInformation := &data.DLNGUUPTNLInformation
	upTransportLayerInformation.Present = ngapType.UPTransportLayerInformationPresentGTPTunnel
	upTransportLayerInformation.GTPTunnel = new(ngapType.GTPTunnel)
	upTransportLayerInformation.GTPTunnel.GTPTEID.Value = aper.OctetString("\x00\x00\x00\x01")
	upTransportLayerInformation.GTPTunnel.TransportLayerAddress = ngapConvert.IPAddressToNgap(IT_IP, "")

	// Qos Flow Setup Response List
	qosFlowSetupResponseItem := ngapType.QosFlowItemWithDataForwarding{
		QosFlowIdentifier: ngapType.QosFlowIdentifier{
			Value: 9,
		},
	}

	data.DLForwardingUPTNLInformation = new(ngapType.UPTransportLayerInformation)
	dlForwardingUPTNLInfo := data.DLForwardingUPTNLInformation
	dlForwardingUPTNLInfo.Present = ngapType.UPTransportLayerInformationPresentGTPTunnel
	dlForwardingUPTNLInfo.GTPTunnel = new(ngapType.GTPTunnel)
	dlForwardingUPTNLInfo.GTPTunnel.GTPTEID.Value = aper.OctetString("\x00\x00\x00\x02")
	dlForwardingUPTNLInfo.GTPTunnel.TransportLayerAddress = ngapConvert.IPAddressToNgap(IT_IP, "")

	data.QosFlowSetupResponseList.List = append(data.QosFlowSetupResponseList.List, qosFlowSetupResponseItem)

	return data
}

func GetHandoverRequestAcknowledgeTransfer() []byte {
	data := buildHandoverRequestAcknowledgeTransfer()
	encodeData, err := aper.MarshalWithParams(data, "valueExt")
	if err != nil {
		fatal.Fatalf("aper MarshalWithParams error in GetHandoverRequestAcknowledgeTransfer: %+v", err)
	}
	return encodeData
}

func buildHandoverRequestAcknowledge(amfUeNgapID, ranUeNgapID int64) (pdu ngapType.NGAPPDU) {
	pdu.Present = ngapType.NGAPPDUPresentSuccessfulOutcome
	pdu.SuccessfulOutcome = new(ngapType.SuccessfulOutcome)

	successfulOutcome := pdu.SuccessfulOutcome
	successfulOutcome.ProcedureCode.Value = ngapType.ProcedureCodeHandoverResourceAllocation
	successfulOutcome.Criticality.Value = ngapType.CriticalityPresentReject

	successfulOutcome.Value.Present = ngapType.SuccessfulOutcomePresentHandoverRequestAcknowledge
	successfulOutcome.Value.HandoverRequestAcknowledge = new(ngapType.HandoverRequestAcknowledge)

	handoverRequestAcknowledge := successfulOutcome.Value.HandoverRequestAcknowledge
	handoverRequestAcknowledgeIEs := &handoverRequestAcknowledge.ProtocolIEs

	// AMF UE NGAP ID
	ie := ngapType.HandoverRequestAcknowledgeIEs{}
	ie.Id.Value = ngapType.ProtocolIEIDAMFUENGAPID
	ie.Criticality.Value = ngapType.CriticalityPresentIgnore
	ie.Value.Present = ngapType.HandoverRequestAcknowledgeIEsPresentAMFUENGAPID
	ie.Value.AMFUENGAPID = new(ngapType.AMFUENGAPID)

	aMFUENGAPID := ie.Value.AMFUENGAPID
	aMFUENGAPID.Value = amfUeNgapID

	handoverRequestAcknowledgeIEs.List = append(handoverRequestAcknowledgeIEs.List, ie)

	// RAN UE NGAP ID
	ie = ngapType.HandoverRequestAcknowledgeIEs{}
	ie.Id.Value = ngapType.ProtocolIEIDRANUENGAPID
	ie.Criticality.Value = ngapType.CriticalityPresentIgnore
	ie.Value.Present = ngapType.HandoverRequestAcknowledgeIEsPresentRANUENGAPID
	ie.Value.RANUENGAPID = new(ngapType.RANUENGAPID)

	rANUENGAPID := ie.Value.RANUENGAPID
	rANUENGAPID.Value = ranUeNgapID

	handoverRequestAcknowledgeIEs.List = append(handoverRequestAcknowledgeIEs.List, ie)

	// PDU Session Resource Admitted List
	ie = ngapType.HandoverRequestAcknowledgeIEs{}
	ie.Id.Value = ngapType.ProtocolIEIDPDUSessionResourceAdmittedList
	ie.Criticality.Value = ngapType.CriticalityPresentIgnore
	ie.Value.Present = ngapType.HandoverRequestAcknowledgeIEsPresentPDUSessionResourceAdmittedList
	ie.Value.PDUSessionResourceAdmittedList = new(ngapType.PDUSessionResourceAdmittedList)

	pDUSessionResourceAdmittedList := ie.Value.PDUSessionResourceAdmittedList

	// PDU Session Resource Admitted Item
	pDUSessionResourceAdmittedItem := ngapType.PDUSessionResourceAdmittedItem{}
	pDUSessionResourceAdmittedItem.PDUSessionID.Value = 10
	pDUSessionResourceAdmittedItem.HandoverRequestAcknowledgeTransfer = GetHandoverRequestAcknowledgeTransfer()

	pDUSessionResourceAdmittedList.List = append(pDUSessionResourceAdmittedList.List, pDUSessionResourceAdmittedItem)

	handoverRequestAcknowledgeIEs.List = append(handoverRequestAcknowledgeIEs.List, ie)

	// Target To Source TransparentContainer
	ie = ngapType.HandoverRequestAcknowledgeIEs{}
	ie.Id.Value = ngapType.ProtocolIEIDTargetToSourceTransparentContainer
	ie.Criticality.Value = ngapType.CriticalityPresentReject
	ie.Value.Present = ngapType.HandoverRequestAcknowledgeIEsPresentTargetToSourceTransparentContainer
	ie.Value.TargetToSourceTransparentContainer = new(ngapType.TargetToSourceTransparentContainer)

	targetToSourceTransparentContainer := ie.Value.TargetToSourceTransparentContainer
	targetToSourceTransparentContainer.Value = aper.OctetString("\x00\x01\x00\x00")

	handoverRequestAcknowledgeIEs.List = append(handoverRequestAcknowledgeIEs.List, ie)

	return pdu
}

func GetHandoverRequestAcknowledge(amfUeNgapID, ranUeNgapID int64) ([]byte, error) {
	return ngap.Encoder(buildHandoverRequestAcknowledge(amfUeNgapID, ranUeNgapID))
}

func buildHandoverNotify(amfUeNgapID, ranUeNgapID int64) (pdu ngapType.NGAPPDU) {
	pdu.Present = ngapType.NGAPPDUPresentInitiatingMessage
	pdu.InitiatingMessage = new(ngapType.InitiatingMessage)

	initiatingMessage := pdu.InitiatingMessage
	initiatingMessage.ProcedureCode.Value = ngapType.ProcedureCodeHandoverNotification
	initiatingMessage.Criticality.Value = ngapType.CriticalityPresentIgnore

	initiatingMessage.Value.Present = ngapType.InitiatingMessagePresentHandoverNotify
	initiatingMessage.Value.HandoverNotify = new(ngapType.HandoverNotify)

	handoverNotify := initiatingMessage.Value.HandoverNotify
	handoverNotifyIEs := &handoverNotify.ProtocolIEs

	// AMF UE NGAP ID
	ie := ngapType.HandoverNotifyIEs{}
	ie.Id.Value = ngapType.ProtocolIEIDAMFUENGAPID
	ie.Criticality.Value = ngapType.CriticalityPresentReject
	ie.Value.Present = ngapType.HandoverNotifyIEsPresentAMFUENGAPID
	ie.Value.AMFUENGAPID = new(ngapType.AMFUENGAPID)

	aMFUENGAPID := ie.Value.AMFUENGAPID
	aMFUENGAPID.Value = amfUeNgapID

	handoverNotifyIEs.List = append(handoverNotifyIEs.List, ie)

	// RAN UE NGAP ID
	ie = ngapType.HandoverNotifyIEs{}
	ie.Id.Value = ngapType.ProtocolIEIDRANUENGAPID
	ie.Criticality.Value = ngapType.CriticalityPresentReject
	ie.Value.Present = ngapType.HandoverNotifyIEsPresentRANUENGAPID
	ie.Value.RANUENGAPID = new(ngapType.RANUENGAPID)

	rANUENGAPID := ie.Value.RANUENGAPID
	rANUENGAPID.Value = ranUeNgapID

	handoverNotifyIEs.List = append(handoverNotifyIEs.List, ie)

	// User Location Information
	ie = ngapType.HandoverNotifyIEs{}
	ie.Id.Value = ngapType.ProtocolIEIDUserLocationInformation
	ie.Criticality.Value = ngapType.CriticalityPresentReject
	ie.Value.Present = ngapType.HandoverNotifyIEsPresentUserLocationInformation
	ie.Value.UserLocationInformation = new(ngapType.UserLocationInformation)

	userLocationInformation := ie.Value.UserLocationInformation
	userLocationInformation.Present = ngapType.UserLocationInformationPresentUserLocationInformationEUTRA
	userLocationInformation.UserLocationInformationEUTRA = new(ngapType.UserLocationInformationEUTRA)

	userLocationInformationEUTRA := userLocationInformation.UserLocationInformationEUTRA
	userLocationInformationEUTRA.TAI.PLMNIdentity.Value = aper.OctetString(PLMN_OCT)
	userLocationInformationEUTRA.TAI.TAC.Value = aper.OctetString("\x00\x00\x01")

	userLocationInformationEUTRA.EUTRACGI.PLMNIdentity.Value = aper.OctetString(PLMN_OCT)
	userLocationInformationEUTRA.EUTRACGI.EUTRACellIdentity.Value = aper.BitString{
		Bytes:     []byte{0x24, 0x16, 0x08, 0xFF},
		BitLength: 28,
	}

	handoverNotifyIEs.List = append(handoverNotifyIEs.List, ie)

	return pdu
}

func GetHandoverNotify(amfUeNgapID, ranUeNgapID int64) ([]byte, error) {
	return ngap.Encoder(buildHandoverNotify(amfUeNgapID, ranUeNgapID))
}

func buildPDUSessionResourceSetupResponseForPaging(amfUeNgapID, ranUeNgapID int64, ipv4 string) (pdu ngapType.NGAPPDU) {
	pdu.Present = ngapType.NGAPPDUPresentSuccessfulOutcome
	pdu.SuccessfulOutcome = new(ngapType.SuccessfulOutcome)

	successfulOutcome := pdu.SuccessfulOutcome
	successfulOutcome.ProcedureCode.Value = ngapType.ProcedureCodePDUSessionResourceSetup
	successfulOutcome.Criticality.Value = ngapType.CriticalityPresentReject

	successfulOutcome.Value.Present = ngapType.SuccessfulOutcomePresentPDUSessionResourceSetupResponse
	successfulOutcome.Value.PDUSessionResourceSetupResponse = new(ngapType.PDUSessionResourceSetupResponse)

	pDUSessionResourceSetupResponse := successfulOutcome.Value.PDUSessionResourceSetupResponse
	pDUSessionResourceSetupResponseIEs := &pDUSessionResourceSetupResponse.ProtocolIEs

	// AMF UE NGAP ID
	ie := ngapType.PDUSessionResourceSetupResponseIEs{}
	ie.Id.Value = ngapType.ProtocolIEIDAMFUENGAPID
	ie.Criticality.Value = ngapType.CriticalityPresentIgnore
	ie.Value.Present = ngapType.PDUSessionResourceSetupResponseIEsPresentAMFUENGAPID
	ie.Value.AMFUENGAPID = new(ngapType.AMFUENGAPID)

	aMFUENGAPID := ie.Value.AMFUENGAPID
	aMFUENGAPID.Value = amfUeNgapID

	pDUSessionResourceSetupResponseIEs.List = append(pDUSessionResourceSetupResponseIEs.List, ie)

	// RAN UE NGAP ID
	ie = ngapType.PDUSessionResourceSetupResponseIEs{}
	ie.Id.Value = ngapType.ProtocolIEIDRANUENGAPID
	ie.Criticality.Value = ngapType.CriticalityPresentIgnore
	ie.Value.Present = ngapType.PDUSessionResourceSetupResponseIEsPresentRANUENGAPID
	ie.Value.RANUENGAPID = new(ngapType.RANUENGAPID)

	rANUENGAPID := ie.Value.RANUENGAPID
	rANUENGAPID.Value = ranUeNgapID

	pDUSessionResourceSetupResponseIEs.List = append(pDUSessionResourceSetupResponseIEs.List, ie)

	// PDU Session Resource Setup Response List
	ie = ngapType.PDUSessionResourceSetupResponseIEs{}
	ie.Id.Value = ngapType.ProtocolIEIDPDUSessionResourceSetupListSURes
	ie.Criticality.Value = ngapType.CriticalityPresentIgnore
	ie.Value.Present = ngapType.PDUSessionResourceSetupResponseIEsPresentPDUSessionResourceSetupListSURes
	ie.Value.PDUSessionResourceSetupListSURes = new(ngapType.PDUSessionResourceSetupListSURes)

	pDUSessionResourceSetupListSURes := ie.Value.PDUSessionResourceSetupListSURes

	// PDU Session Resource Setup Response Item in PDU Session Resource Setup Response List
	pDUSessionResourceSetupItemSURes := ngapType.PDUSessionResourceSetupItemSURes{}
	pDUSessionResourceSetupItemSURes.PDUSessionID.Value = 10

	pDUSessionResourceSetupItemSURes.PDUSessionResourceSetupResponseTransfer =
		GetPDUSessionResourceSetupResponseTransfer(ipv4)

	pDUSessionResourceSetupListSURes.List = append(pDUSessionResourceSetupListSURes.List, pDUSessionResourceSetupItemSURes)

	pDUSessionResourceSetupResponseIEs.List = append(pDUSessionResourceSetupResponseIEs.List, ie)

	// PDU Session Resource Failed to Setup List
	ie = ngapType.PDUSessionResourceSetupResponseIEs{}
	ie.Id.Value = ngapType.ProtocolIEIDPDUSessionResourceFailedToSetupListSURes
	ie.Criticality.Value = ngapType.CriticalityPresentIgnore
	ie.Value.Present = ngapType.PDUSessionResourceSetupResponseIEsPresentPDUSessionResourceFailedToSetupListSURes
	ie.Value.PDUSessionResourceFailedToSetupListSURes = new(ngapType.PDUSessionResourceFailedToSetupListSURes)

	return pdu
}

func GetPDUSessionResourceSetupResponseForPaging(amfUeNgapID, ranUeNgapID int64, ipv4 string) ([]byte, error) {
	return ngap.Encoder(buildPDUSessionResourceSetupResponseForPaging(amfUeNgapID, ranUeNgapID, ipv4))
}

func buildHandoverRequiredTransfer() (data ngapType.HandoverRequiredTransfer) {
	data.DirectForwardingPathAvailability = new(ngapType.DirectForwardingPathAvailability)
	data.DirectForwardingPathAvailability.Value = ngapType.DirectForwardingPathAvailabilityPresentDirectPathAvailable
	return data
}

func GetHandoverRequiredTransfer() []byte {
	data := buildHandoverRequiredTransfer()
	encodeData, err := aper.MarshalWithParams(data, "valueExt")
	if err != nil {
		fatal.Fatalf("aper MarshalWithParams error in GetHandoverRequiredTransfer: %+v", err)
	}
	return encodeData
}

func buildSourceToTargetTransparentTransfer(
	targetGNBID []byte, targetCellID []byte,
) (data ngapType.SourceNGRANNodeToTargetNGRANNodeTransparentContainer) {
	// RRC Container
	data.RRCContainer.Value = aper.OctetString("\x00\x00\x11")

	// PDU Session Resource Information List
	data.PDUSessionResourceInformationList = new(ngapType.PDUSessionResourceInformationList)
	infoItem := ngapType.PDUSessionResourceInformationItem{}
	infoItem.PDUSessionID.Value = 10
	qosItem := ngapType.QosFlowInformationItem{}
	qosItem.QosFlowIdentifier.Value = 1
	infoItem.QosFlowInformationList.List = append(infoItem.QosFlowInformationList.List, qosItem)
	data.PDUSessionResourceInformationList.List = append(data.PDUSessionResourceInformationList.List, infoItem)

	// Target Cell ID
	data.TargetCellID.Present = ngapType.TargetIDPresentTargetRANNodeID
	data.TargetCellID.NRCGI = new(ngapType.NRCGI)
	data.TargetCellID.NRCGI.PLMNIdentity = PLMN
	data.TargetCellID.NRCGI.NRCellIdentity.Value = aper.BitString{
		Bytes:     append(targetGNBID, targetCellID...),
		BitLength: 36,
	}

	// UE History Information
	lastVisitedCellItem := ngapType.LastVisitedCellItem{}
	lastVisitedCellInfo := &lastVisitedCellItem.LastVisitedCellInformation
	lastVisitedCellInfo.Present = ngapType.LastVisitedCellInformationPresentNGRANCell
	lastVisitedCellInfo.NGRANCell = new(ngapType.LastVisitedNGRANCellInformation)
	ngRanCell := lastVisitedCellInfo.NGRANCell
	ngRanCell.GlobalCellID.Present = ngapType.NGRANCGIPresentNRCGI
	ngRanCell.GlobalCellID.NRCGI = new(ngapType.NRCGI)
	ngRanCell.GlobalCellID.NRCGI.PLMNIdentity = PLMN
	ngRanCell.GlobalCellID.NRCGI.NRCellIdentity.Value = aper.BitString{
		Bytes:     []byte{0x00, 0x00, 0x00, 0x00, 0x10},
		BitLength: 36,
	}
	ngRanCell.CellType.CellSize.Value = ngapType.CellSizePresentVerysmall
	ngRanCell.TimeUEStayedInCell.Value = 10

	data.UEHistoryInformation.List = append(data.UEHistoryInformation.List, lastVisitedCellItem)
	return data
}

func GetSourceToTargetTransparentTransfer(targetGNBID []byte, targetCellID []byte) []byte {
	data := buildSourceToTargetTransparentTransfer(targetGNBID, targetCellID)
	encodeData, err := aper.MarshalWithParams(data, "valueExt")
	if err != nil {
		fatal.Fatalf("aper MarshalWithParams error in GetSourceToTargetTransparentTransfer: %+v", err)
	}
	return encodeData
}

func buildHandoverRequired(
	amfUeNgapID, ranUeNgapID int64, targetGNBID []byte, targetCellID []byte,
) (pdu ngapType.NGAPPDU) {
	pdu.Present = ngapType.NGAPPDUPresentInitiatingMessage
	pdu.InitiatingMessage = new(ngapType.InitiatingMessage)

	initiatingMessage := pdu.InitiatingMessage
	initiatingMessage.ProcedureCode.Value = ngapType.ProcedureCodeHandoverPreparation
	initiatingMessage.Criticality.Value = ngapType.CriticalityPresentReject

	initiatingMessage.Value.Present = ngapType.InitiatingMessagePresentHandoverRequired
	initiatingMessage.Value.HandoverRequired = new(ngapType.HandoverRequired)

	handoverRequired := initiatingMessage.Value.HandoverRequired
	handoverRequiredIEs := &handoverRequired.ProtocolIEs

	// AMF UE NGAP ID
	ie := ngapType.HandoverRequiredIEs{}
	ie.Id.Value = ngapType.ProtocolIEIDAMFUENGAPID
	ie.Criticality.Value = ngapType.CriticalityPresentReject
	ie.Value.Present = ngapType.HandoverRequiredIEsPresentAMFUENGAPID
	ie.Value.AMFUENGAPID = new(ngapType.AMFUENGAPID)

	aMFUENGAPID := ie.Value.AMFUENGAPID
	aMFUENGAPID.Value = amfUeNgapID

	handoverRequiredIEs.List = append(handoverRequiredIEs.List, ie)

	// RAN UE NGAP ID
	ie = ngapType.HandoverRequiredIEs{}
	ie.Id.Value = ngapType.ProtocolIEIDRANUENGAPID
	ie.Criticality.Value = ngapType.CriticalityPresentReject
	ie.Value.Present = ngapType.HandoverRequiredIEsPresentRANUENGAPID
	ie.Value.RANUENGAPID = new(ngapType.RANUENGAPID)

	rANUENGAPID := ie.Value.RANUENGAPID
	rANUENGAPID.Value = ranUeNgapID

	handoverRequiredIEs.List = append(handoverRequiredIEs.List, ie)

	// Handover Type
	ie = ngapType.HandoverRequiredIEs{}
	ie.Id.Value = ngapType.ProtocolIEIDHandoverType
	ie.Criticality.Value = ngapType.CriticalityPresentReject
	ie.Value.Present = ngapType.HandoverRequiredIEsPresentHandoverType
	ie.Value.HandoverType = new(ngapType.HandoverType)

	handoverType := ie.Value.HandoverType
	handoverType.Value = ngapType.HandoverTypePresentIntra5gs

	handoverRequiredIEs.List = append(handoverRequiredIEs.List, ie)

	// Cause
	ie = ngapType.HandoverRequiredIEs{}
	ie.Id.Value = ngapType.ProtocolIEIDCause
	ie.Criticality.Value = ngapType.CriticalityPresentIgnore
	ie.Value.Present = ngapType.HandoverRequiredIEsPresentCause
	ie.Value.Cause = new(ngapType.Cause)

	cause := ie.Value.Cause
	cause.Present = ngapType.CausePresentRadioNetwork
	cause.RadioNetwork = new(ngapType.CauseRadioNetwork)
	cause.RadioNetwork.Value = ngapType.CauseRadioNetworkPresentHandoverDesirableForRadioReason

	handoverRequiredIEs.List = append(handoverRequiredIEs.List, ie)

	// Target ID
	ie = ngapType.HandoverRequiredIEs{}
	ie.Id.Value = ngapType.ProtocolIEIDTargetID
	ie.Criticality.Value = ngapType.CriticalityPresentReject
	ie.Value.Present = ngapType.HandoverRequiredIEsPresentTargetID
	ie.Value.TargetID = new(ngapType.TargetID)

	targetID := ie.Value.TargetID
	targetID.Present = ngapType.TargetIDPresentTargetRANNodeID
	targetID.TargetRANNodeID = new(ngapType.TargetRANNodeID)

	targetRANNodeID := targetID.TargetRANNodeID
	targetRANNodeID.GlobalRANNodeID.Present = ngapType.GlobalRANNodeIDPresentGlobalGNBID
	targetRANNodeID.GlobalRANNodeID.GlobalGNBID = new(ngapType.GlobalGNBID)

	globalRANNodeID := targetRANNodeID.GlobalRANNodeID
	globalRANNodeID.GlobalGNBID.PLMNIdentity.Value = aper.OctetString(PLMN_OCT)
	globalRANNodeID.GlobalGNBID.GNBID.Present = ngapType.GNBIDPresentGNBID

	globalRANNodeID.GlobalGNBID.GNBID.GNBID = new(aper.BitString)

	gNBID := globalRANNodeID.GlobalGNBID.GNBID.GNBID

	*gNBID = aper.BitString{
		Bytes:     targetGNBID,
		BitLength: uint64(len(targetGNBID) * 8),
	}

	targetRANNodeID.SelectedTAI.PLMNIdentity.Value = aper.OctetString(PLMN_OCT)
	targetRANNodeID.SelectedTAI.TAC.Value = aper.OctetString("\x00\x00\x01")

	handoverRequiredIEs.List = append(handoverRequiredIEs.List, ie)

	// PDU Session Resource List
	ie = ngapType.HandoverRequiredIEs{}
	ie.Id.Value = ngapType.ProtocolIEIDPDUSessionResourceListHORqd
	ie.Criticality.Value = ngapType.CriticalityPresentReject
	ie.Value.Present = ngapType.HandoverRequiredIEsPresentPDUSessionResourceListHORqd
	ie.Value.PDUSessionResourceListHORqd = new(ngapType.PDUSessionResourceListHORqd)

	pDUSessionResourceListHORqd := ie.Value.PDUSessionResourceListHORqd

	// PDU Session Resource Item (in PDU Session Resource List)
	pDUSessionResourceItem := ngapType.PDUSessionResourceItemHORqd{}
	pDUSessionResourceItem.PDUSessionID.Value = 10
	pDUSessionResourceItem.HandoverRequiredTransfer = GetHandoverRequiredTransfer()

	pDUSessionResourceListHORqd.List = append(pDUSessionResourceListHORqd.List, pDUSessionResourceItem)

	handoverRequiredIEs.List = append(handoverRequiredIEs.List, ie)

	// Source to Target Transparent Container
	ie = ngapType.HandoverRequiredIEs{}
	ie.Id.Value = ngapType.ProtocolIEIDSourceToTargetTransparentContainer
	ie.Criticality.Value = ngapType.CriticalityPresentReject
	ie.Value.Present = ngapType.HandoverRequiredIEsPresentSourceToTargetTransparentContainer
	ie.Value.SourceToTargetTransparentContainer = new(ngapType.SourceToTargetTransparentContainer)

	ie.Value.SourceToTargetTransparentContainer.Value = GetSourceToTargetTransparentTransfer(targetGNBID, targetCellID)

	handoverRequiredIEs.List = append(handoverRequiredIEs.List, ie)

	return pdu
}

func GetHandoverRequired(amfUeNgapID, ranUeNgapID int64, targetGNBID []byte, targetCellID []byte) ([]byte, error) {
	return ngap.Encoder(buildHandoverRequired(amfUeNgapID, ranUeNgapID, targetGNBID, targetCellID))
}

func buildPathSwitchRequestTransfer() (data ngapType.PathSwitchRequestTransfer) {
	// DL NG-U UP TNL information
	upTransportLayerInformation := &data.DLNGUUPTNLInformation
	upTransportLayerInformation.Present = ngapType.UPTransportLayerInformationPresentGTPTunnel
	upTransportLayerInformation.GTPTunnel = new(ngapType.GTPTunnel)
	upTransportLayerInformation.GTPTunnel.GTPTEID.Value = aper.OctetString("\x00\x00\x00\x02")
	upTransportLayerInformation.GTPTunnel.TransportLayerAddress = ngapConvert.IPAddressToNgap(IT_IP, "")

	// Qos Flow Accepted List
	qosFlowAcceptedList := &data.QosFlowAcceptedList
	qosFlowAcceptedItem := ngapType.QosFlowAcceptedItem{
		QosFlowIdentifier: ngapType.QosFlowIdentifier{
			Value: 1,
		},
	}
	qosFlowAcceptedList.List = append(qosFlowAcceptedList.List, qosFlowAcceptedItem)

	return data
}

func GetPathSwitchRequestTransfer() []byte {
	data := buildPathSwitchRequestTransfer()
	encodeData, err := aper.MarshalWithParams(data, "valueExt")
	if err != nil {
		fatal.Fatalf("aper MarshalWithParams error in GetPathSwitchRequestTransfer: %+v", err)
	}
	return encodeData
}

func buildPathSwitchRequestSetupFailedTransfer() (data ngapType.PathSwitchRequestSetupFailedTransfer) {
	// Cause
	data.Cause = ngapType.Cause{
		Present: ngapType.CausePresentTransport,
		Transport: &ngapType.CauseTransport{
			Value: ngapType.CauseTransportPresentTransportResourceUnavailable,
		},
	}

	return data
}

func GetPathSwitchRequestSetupFailedTransfer() []byte {
	data := buildPathSwitchRequestSetupFailedTransfer()
	encodeData, err := aper.MarshalWithParams(data, "valueExt")
	if err != nil {
		fatal.Fatalf("aper MarshalWithParams error in GetPathSwitchRequestSetupFailedTransfer: %+v", err)
	}
	return encodeData
}

func buildPathSwitchRequest(sourceAmfUeNgapID, ranUeNgapID int64) (pdu ngapType.NGAPPDU) {
	pdu.Present = ngapType.NGAPPDUPresentInitiatingMessage
	pdu.InitiatingMessage = new(ngapType.InitiatingMessage)

	initiatingMessage := pdu.InitiatingMessage
	initiatingMessage.ProcedureCode.Value = ngapType.ProcedureCodePathSwitchRequest
	initiatingMessage.Criticality.Value = ngapType.CriticalityPresentReject

	initiatingMessage.Value.Present = ngapType.InitiatingMessagePresentPathSwitchRequest
	initiatingMessage.Value.PathSwitchRequest = new(ngapType.PathSwitchRequest)

	pathSwitchRequest := initiatingMessage.Value.PathSwitchRequest
	pathSwitchRequestIEs := &pathSwitchRequest.ProtocolIEs

	// RAN UE NGAP ID
	ie := ngapType.PathSwitchRequestIEs{}
	ie.Id.Value = ngapType.ProtocolIEIDRANUENGAPID
	ie.Criticality.Value = ngapType.CriticalityPresentReject
	ie.Value.Present = ngapType.PathSwitchRequestIEsPresentRANUENGAPID
	ie.Value.RANUENGAPID = new(ngapType.RANUENGAPID)

	rANUENGAPID := ie.Value.RANUENGAPID
	rANUENGAPID.Value = ranUeNgapID

	pathSwitchRequestIEs.List = append(pathSwitchRequestIEs.List, ie)

	// Source AMF UE NGAP ID (equal to AMF UE NGAP ID)
	ie = ngapType.PathSwitchRequestIEs{}
	ie.Id.Value = ngapType.ProtocolIEIDSourceAMFUENGAPID
	ie.Criticality.Value = ngapType.CriticalityPresentReject
	ie.Value.Present = ngapType.PathSwitchRequestIEsPresentSourceAMFUENGAPID
	ie.Value.SourceAMFUENGAPID = new(ngapType.AMFUENGAPID)

	aMFUENGAPID := ie.Value.SourceAMFUENGAPID
	aMFUENGAPID.Value = sourceAmfUeNgapID

	pathSwitchRequestIEs.List = append(pathSwitchRequestIEs.List, ie)

	// User Location Information
	ie = ngapType.PathSwitchRequestIEs{}
	ie.Id.Value = ngapType.ProtocolIEIDUserLocationInformation
	ie.Criticality.Value = ngapType.CriticalityPresentIgnore
	ie.Value.Present = ngapType.PathSwitchRequestIEsPresentUserLocationInformation
	ie.Value.UserLocationInformation = new(ngapType.UserLocationInformation)

	userLocationInformation := ie.Value.UserLocationInformation
	userLocationInformation.Present = ngapType.UserLocationInformationPresentUserLocationInformationNR
	userLocationInformation.UserLocationInformationNR = new(ngapType.UserLocationInformationNR)

	userLocationInformationNR := userLocationInformation.UserLocationInformationNR
	userLocationInformationNR.NRCGI.PLMNIdentity.Value = aper.OctetString(PLMN_OCT)
	userLocationInformationNR.NRCGI.NRCellIdentity.Value = aper.BitString{
		Bytes:     []byte{0x00, 0x00, 0x00, 0x00, 0x20},
		BitLength: 36,
	}

	userLocationInformationNR.TAI.PLMNIdentity.Value = aper.OctetString(PLMN_OCT)
	userLocationInformationNR.TAI.TAC.Value = aper.OctetString("\x00\x00\x01")

	pathSwitchRequestIEs.List = append(pathSwitchRequestIEs.List, ie)

	// UE Security Capabilities
	ie = ngapType.PathSwitchRequestIEs{}
	ie.Id.Value = ngapType.ProtocolIEIDUESecurityCapabilities
	ie.Criticality.Value = ngapType.CriticalityPresentIgnore
	ie.Value.Present = ngapType.PathSwitchRequestIEsPresentUESecurityCapabilities
	ie.Value.UESecurityCapabilities = new(ngapType.UESecurityCapabilities)

	uESecurityCapabilities := ie.Value.UESecurityCapabilities
	uESecurityCapabilities.NRencryptionAlgorithms.Value = aper.BitString{
		Bytes:     []byte{0xff, 0xff},
		BitLength: 16,
	}
	uESecurityCapabilities.NRintegrityProtectionAlgorithms.Value = aper.BitString{
		Bytes:     []byte{0xff, 0xff},
		BitLength: 16,
	}
	uESecurityCapabilities.EUTRAencryptionAlgorithms.Value = aper.BitString{
		Bytes:     []byte{0xff, 0xff},
		BitLength: 16,
	}
	uESecurityCapabilities.EUTRAintegrityProtectionAlgorithms.Value = aper.BitString{
		Bytes:     []byte{0xff, 0xff},
		BitLength: 16,
	}

	pathSwitchRequestIEs.List = append(pathSwitchRequestIEs.List, ie)

	// PDU Session Resource to be Switched in Downlink List
	ie = ngapType.PathSwitchRequestIEs{}
	ie.Id.Value = ngapType.ProtocolIEIDPDUSessionResourceToBeSwitchedDLList
	ie.Criticality.Value = ngapType.CriticalityPresentReject
	ie.Value.Present = ngapType.PathSwitchRequestIEsPresentPDUSessionResourceToBeSwitchedDLList
	ie.Value.PDUSessionResourceToBeSwitchedDLList = new(ngapType.PDUSessionResourceToBeSwitchedDLList)

	pDUSessionResourceToBeSwitchedDLList := ie.Value.PDUSessionResourceToBeSwitchedDLList

	// PDU Session Resource to be Switched in Downlink Item (in PDU Session Resource to be Switched in Downlink List)
	pDUSessionResourceToBeSwitchedDLItem := ngapType.PDUSessionResourceToBeSwitchedDLItem{}
	pDUSessionResourceToBeSwitchedDLItem.PDUSessionID.Value = 10
	pDUSessionResourceToBeSwitchedDLItem.PathSwitchRequestTransfer = GetPathSwitchRequestTransfer()

	pDUSessionResourceToBeSwitchedDLList.List =
		append(pDUSessionResourceToBeSwitchedDLList.List, pDUSessionResourceToBeSwitchedDLItem)

	pathSwitchRequestIEs.List = append(pathSwitchRequestIEs.List, ie)

	// PDU Session Resource Failed to Setup List
	ie = ngapType.PathSwitchRequestIEs{}
	ie.Id.Value = ngapType.ProtocolIEIDPDUSessionResourceFailedToSetupListPSReq
	ie.Criticality.Value = ngapType.CriticalityPresentIgnore
	ie.Value.Present = ngapType.PathSwitchRequestIEsPresentPDUSessionResourceFailedToSetupListPSReq
	ie.Value.PDUSessionResourceFailedToSetupListPSReq = new(ngapType.PDUSessionResourceFailedToSetupListPSReq)

	pDUSessionResourceFailedToSetupListPSReq := ie.Value.PDUSessionResourceFailedToSetupListPSReq

	// PDU Session Resource Failed to Setup Item (in PDU Session Resource Failed to Setup List)
	pDUSessionResourceFailedToSetupItemPSReq := ngapType.PDUSessionResourceFailedToSetupItemPSReq{}
	pDUSessionResourceFailedToSetupItemPSReq.PDUSessionID.Value = 11
	pDUSessionResourceFailedToSetupItemPSReq.PathSwitchRequestSetupFailedTransfer =
		GetPathSwitchRequestSetupFailedTransfer()

	pDUSessionResourceFailedToSetupListPSReq.List =
		append(pDUSessionResourceFailedToSetupListPSReq.List, pDUSessionResourceFailedToSetupItemPSReq)

	pathSwitchRequestIEs.List = append(pathSwitchRequestIEs.List, ie)

	return pdu
}

// GetPathSwitchRequest truncates the IE list to the first 5 entries (dropping the
// PDU Session Resource Failed to Setup List), matching the reference test's
// GetPathSwitchRequest which excludes that IE since no PDU session in this test
// scenario actually fails to set up.
func GetPathSwitchRequest(amfUeNgapID, ranUeNgapID int64) ([]byte, error) {
	message := buildPathSwitchRequest(amfUeNgapID, ranUeNgapID)
	message.InitiatingMessage.Value.PathSwitchRequest.ProtocolIEs.List =
		message.InitiatingMessage.Value.PathSwitchRequest.ProtocolIEs.List[0:5]
	return ngap.Encoder(message)
}

// buildPDUSessionResourceSetupResponseTransferWithDC is like
// buildPDUSessionResourceSetupResponseTransfer but additionally splits the QoS flow to
// a secondary RAN via AdditionalDLQosFlowPerTNLInformation, for NR dual-connectivity
// (NR-DC) tests where a single PDU session's downlink traffic is delivered through both
// a master and a secondary RAN simultaneously.
func buildPDUSessionResourceSetupResponseTransferWithDC(
	mranDlTeid, sranDlTeid string,
) (data ngapType.PDUSessionResourceSetupResponseTransfer) {
	// QoS Flow per TNL Information (master RAN)
	qosFlowPerTNLInformation := &data.DLQosFlowPerTNLInformation
	qosFlowPerTNLInformation.UPTransportLayerInformation.Present = ngapType.UPTransportLayerInformationPresentGTPTunnel

	upTransportLayerInformation := &qosFlowPerTNLInformation.UPTransportLayerInformation
	upTransportLayerInformation.Present = ngapType.UPTransportLayerInformationPresentGTPTunnel
	upTransportLayerInformation.GTPTunnel = new(ngapType.GTPTunnel)
	upTransportLayerInformation.GTPTunnel.GTPTEID.Value = aper.OctetString(mranDlTeid)
	upTransportLayerInformation.GTPTunnel.TransportLayerAddress = ngapConvert.IPAddressToNgap(IT_IP, "")

	associatedQosFlowList := &qosFlowPerTNLInformation.AssociatedQosFlowList
	associatedQosFlowItem := ngapType.AssociatedQosFlowItem{}
	associatedQosFlowItem.QosFlowIdentifier.Value = 1
	associatedQosFlowList.List = append(associatedQosFlowList.List, associatedQosFlowItem)

	// Additional DL QoS Flow per TNL Information (secondary RAN)
	dcQosFlowPerTNLInformationItem := ngapType.QosFlowPerTNLInformationItem{}
	dcQosFlowPerTNLInformationItem.QosFlowPerTNLInformation.UPTransportLayerInformation.Present =
		ngapType.UPTransportLayerInformationPresentGTPTunnel

	dcUpTransportLayerInformation := &dcQosFlowPerTNLInformationItem.QosFlowPerTNLInformation.UPTransportLayerInformation
	dcUpTransportLayerInformation.Present = ngapType.UPTransportLayerInformationPresentGTPTunnel
	dcUpTransportLayerInformation.GTPTunnel = new(ngapType.GTPTunnel)
	dcUpTransportLayerInformation.GTPTunnel.GTPTEID.Value = aper.OctetString(sranDlTeid)
	dcUpTransportLayerInformation.GTPTunnel.TransportLayerAddress = ngapConvert.IPAddressToNgap(IT_IP_2, "")

	dcAssociatedQosFlowList := &dcQosFlowPerTNLInformationItem.QosFlowPerTNLInformation.AssociatedQosFlowList
	dcAssociatedQosFlowItem := ngapType.AssociatedQosFlowItem{}
	dcAssociatedQosFlowItem.QosFlowIdentifier.Value = 1
	dcAssociatedQosFlowList.List = append(dcAssociatedQosFlowList.List, dcAssociatedQosFlowItem)

	data.AdditionalDLQosFlowPerTNLInformation = new(ngapType.QosFlowPerTNLInformationList)
	data.AdditionalDLQosFlowPerTNLInformation.List =
		append(data.AdditionalDLQosFlowPerTNLInformation.List, dcQosFlowPerTNLInformationItem)

	return data
}

func GetPDUSessionResourceSetupResponseTransferWithDC(mranDlTeid, sranDlTeid string) []byte {
	data := buildPDUSessionResourceSetupResponseTransferWithDC(mranDlTeid, sranDlTeid)
	encodeData, err := aper.MarshalWithParams(data, "valueExt")
	if err != nil {
		fatal.Fatalf("aper MarshalWithParams error in GetPDUSessionResourceSetupResponseTransferWithDC: %+v", err)
	}
	return encodeData
}

func buildPDUSessionResourceSetupResponseWithDC(
	pduSessionId, amfUeNgapId, ranUeNgapId int64, mranDlTeid, sranDlTeid string,
) (pdu ngapType.NGAPPDU) {
	pdu.Present = ngapType.NGAPPDUPresentSuccessfulOutcome
	pdu.SuccessfulOutcome = new(ngapType.SuccessfulOutcome)

	successfulOutcome := pdu.SuccessfulOutcome
	successfulOutcome.ProcedureCode.Value = ngapType.ProcedureCodePDUSessionResourceSetup
	successfulOutcome.Criticality.Value = ngapType.CriticalityPresentReject

	successfulOutcome.Value.Present = ngapType.SuccessfulOutcomePresentPDUSessionResourceSetupResponse
	successfulOutcome.Value.PDUSessionResourceSetupResponse = new(ngapType.PDUSessionResourceSetupResponse)

	pDUSessionResourceSetupResponse := successfulOutcome.Value.PDUSessionResourceSetupResponse
	pDUSessionResourceSetupResponseIEs := &pDUSessionResourceSetupResponse.ProtocolIEs

	// AMF UE NGAP ID
	ie := ngapType.PDUSessionResourceSetupResponseIEs{}
	ie.Id.Value = ngapType.ProtocolIEIDAMFUENGAPID
	ie.Criticality.Value = ngapType.CriticalityPresentIgnore
	ie.Value.Present = ngapType.PDUSessionResourceSetupResponseIEsPresentAMFUENGAPID
	ie.Value.AMFUENGAPID = new(ngapType.AMFUENGAPID)
	ie.Value.AMFUENGAPID.Value = amfUeNgapId
	pDUSessionResourceSetupResponseIEs.List = append(pDUSessionResourceSetupResponseIEs.List, ie)

	// RAN UE NGAP ID
	ie = ngapType.PDUSessionResourceSetupResponseIEs{}
	ie.Id.Value = ngapType.ProtocolIEIDRANUENGAPID
	ie.Criticality.Value = ngapType.CriticalityPresentIgnore
	ie.Value.Present = ngapType.PDUSessionResourceSetupResponseIEsPresentRANUENGAPID
	ie.Value.RANUENGAPID = new(ngapType.RANUENGAPID)
	ie.Value.RANUENGAPID.Value = ranUeNgapId
	pDUSessionResourceSetupResponseIEs.List = append(pDUSessionResourceSetupResponseIEs.List, ie)

	// PDU Session Resource Setup Response List
	ie = ngapType.PDUSessionResourceSetupResponseIEs{}
	ie.Id.Value = ngapType.ProtocolIEIDPDUSessionResourceSetupListSURes
	ie.Criticality.Value = ngapType.CriticalityPresentIgnore
	ie.Value.Present = ngapType.PDUSessionResourceSetupResponseIEsPresentPDUSessionResourceSetupListSURes
	ie.Value.PDUSessionResourceSetupListSURes = new(ngapType.PDUSessionResourceSetupListSURes)

	pDUSessionResourceSetupListSURes := ie.Value.PDUSessionResourceSetupListSURes
	pDUSessionResourceSetupItemSURes := ngapType.PDUSessionResourceSetupItemSURes{}
	pDUSessionResourceSetupItemSURes.PDUSessionID.Value = pduSessionId
	pDUSessionResourceSetupItemSURes.PDUSessionResourceSetupResponseTransfer =
		GetPDUSessionResourceSetupResponseTransferWithDC(mranDlTeid, sranDlTeid)
	pDUSessionResourceSetupListSURes.List = append(pDUSessionResourceSetupListSURes.List, pDUSessionResourceSetupItemSURes)

	pDUSessionResourceSetupResponseIEs.List = append(pDUSessionResourceSetupResponseIEs.List, ie)

	return pdu
}

func GetPDUSessionResourceSetupResponseWithDC(
	pduSessionId, amfUeNgapId, ranUeNgapId int64, mranDlTeid, sranDlTeid string,
) ([]byte, error) {
	return ngap.Encoder(buildPDUSessionResourceSetupResponseWithDC(pduSessionId, amfUeNgapId, ranUeNgapId, mranDlTeid, sranDlTeid))
}

// buildPDUSessionResourceModifyIndicationTransferWithDC mirrors
// buildPDUSessionResourceSetupResponseTransferWithDC but for the RAN-initiated PDU
// Session Resource Modify Indication procedure, used by NR-DC tests to dynamically
// add (enableDC=true) or remove (enableDC=false) the secondary RAN's QoS flow mapping
// mid-session, without re-establishing the PDU session.
func buildPDUSessionResourceModifyIndicationTransferWithDC(
	enableDC bool, mranDlTeid, sranDlTeid string,
) (data ngapType.PDUSessionResourceModifyIndicationTransfer) {
	// QoS Flow per TNL Information (master RAN)
	qosFlowPerTNLInformation := &data.DLQosFlowPerTNLInformation
	qosFlowPerTNLInformation.UPTransportLayerInformation.Present = ngapType.UPTransportLayerInformationPresentGTPTunnel

	upTransportLayerInformation := &qosFlowPerTNLInformation.UPTransportLayerInformation
	upTransportLayerInformation.Present = ngapType.UPTransportLayerInformationPresentGTPTunnel
	upTransportLayerInformation.GTPTunnel = new(ngapType.GTPTunnel)
	upTransportLayerInformation.GTPTunnel.GTPTEID.Value = aper.OctetString(mranDlTeid)
	upTransportLayerInformation.GTPTunnel.TransportLayerAddress = ngapConvert.IPAddressToNgap(IT_IP, "")

	associatedQosFlowList := &qosFlowPerTNLInformation.AssociatedQosFlowList
	associatedQosFlowItem := ngapType.AssociatedQosFlowItem{}
	associatedQosFlowItem.QosFlowIdentifier.Value = 1
	associatedQosFlowList.List = append(associatedQosFlowList.List, associatedQosFlowItem)

	if enableDC {
		// Additional DL QoS Flow per TNL Information (secondary RAN)
		dcQosFlowPerTNLInformationItem := ngapType.QosFlowPerTNLInformationItem{}
		dcQosFlowPerTNLInformationItem.QosFlowPerTNLInformation.UPTransportLayerInformation.Present =
			ngapType.UPTransportLayerInformationPresentGTPTunnel

		dcUpTransportLayerInformation := &dcQosFlowPerTNLInformationItem.QosFlowPerTNLInformation.UPTransportLayerInformation
		dcUpTransportLayerInformation.Present = ngapType.UPTransportLayerInformationPresentGTPTunnel
		dcUpTransportLayerInformation.GTPTunnel = new(ngapType.GTPTunnel)
		dcUpTransportLayerInformation.GTPTunnel.GTPTEID.Value = aper.OctetString(sranDlTeid)
		dcUpTransportLayerInformation.GTPTunnel.TransportLayerAddress = ngapConvert.IPAddressToNgap(IT_IP_2, "")

		dcAssociatedQosFlowList := &dcQosFlowPerTNLInformationItem.QosFlowPerTNLInformation.AssociatedQosFlowList
		dcAssociatedQosFlowItem := ngapType.AssociatedQosFlowItem{}
		dcAssociatedQosFlowItem.QosFlowIdentifier.Value = 1
		dcAssociatedQosFlowList.List = append(dcAssociatedQosFlowList.List, dcAssociatedQosFlowItem)

		data.AdditionalDLQosFlowPerTNLInformation = new(ngapType.QosFlowPerTNLInformationList)
		data.AdditionalDLQosFlowPerTNLInformation.List =
			append(data.AdditionalDLQosFlowPerTNLInformation.List, dcQosFlowPerTNLInformationItem)
	}

	return data
}

func GetPDUSessionResourceModifyIndicationTransferWithDC(enableDC bool, mranDlTeid, sranDlTeid string) []byte {
	data := buildPDUSessionResourceModifyIndicationTransferWithDC(enableDC, mranDlTeid, sranDlTeid)
	encodeData, err := aper.MarshalWithParams(data, "valueExt")
	if err != nil {
		fatal.Fatalf("aper MarshalWithParams error in GetPDUSessionResourceModifyIndicationTransferWithDC: %+v", err)
	}
	return encodeData
}

func buildPDUSessionResourceModifyIndication(
	pduSessionId, amfUeNgapId, ranUeNgapId int64, enableDC bool, mranDlTeid, sranDlTeid string,
) (pdu ngapType.NGAPPDU) {
	pdu.Present = ngapType.NGAPPDUPresentInitiatingMessage
	pdu.InitiatingMessage = new(ngapType.InitiatingMessage)

	initiatingMessage := pdu.InitiatingMessage
	initiatingMessage.ProcedureCode.Value = ngapType.ProcedureCodePDUSessionResourceModifyIndication
	initiatingMessage.Criticality.Value = ngapType.CriticalityPresentReject

	initiatingMessage.Value.Present = ngapType.InitiatingMessagePresentPDUSessionResourceModifyIndication
	initiatingMessage.Value.PDUSessionResourceModifyIndication = new(ngapType.PDUSessionResourceModifyIndication)

	indication := initiatingMessage.Value.PDUSessionResourceModifyIndication
	indicationIEs := &indication.ProtocolIEs

	// AMF UE NGAP ID
	ie := ngapType.PDUSessionResourceModifyIndicationIEs{}
	ie.Id.Value = ngapType.ProtocolIEIDAMFUENGAPID
	ie.Criticality.Value = ngapType.CriticalityPresentIgnore
	ie.Value.Present = ngapType.PDUSessionResourceModifyIndicationIEsPresentAMFUENGAPID
	ie.Value.AMFUENGAPID = new(ngapType.AMFUENGAPID)
	ie.Value.AMFUENGAPID.Value = amfUeNgapId
	indicationIEs.List = append(indicationIEs.List, ie)

	// RAN UE NGAP ID
	ie = ngapType.PDUSessionResourceModifyIndicationIEs{}
	ie.Id.Value = ngapType.ProtocolIEIDRANUENGAPID
	ie.Criticality.Value = ngapType.CriticalityPresentIgnore
	ie.Value.Present = ngapType.PDUSessionResourceModifyIndicationIEsPresentRANUENGAPID
	ie.Value.RANUENGAPID = new(ngapType.RANUENGAPID)
	ie.Value.RANUENGAPID.Value = ranUeNgapId
	indicationIEs.List = append(indicationIEs.List, ie)

	// PDU Session Resource Modify List
	ie = ngapType.PDUSessionResourceModifyIndicationIEs{}
	ie.Id.Value = ngapType.ProtocolIEIDPDUSessionResourceModifyListModInd
	ie.Criticality.Value = ngapType.CriticalityPresentReject
	ie.Value.Present = ngapType.PDUSessionResourceModifyIndicationIEsPresentPDUSessionResourceModifyListModInd
	ie.Value.PDUSessionResourceModifyListModInd = new(ngapType.PDUSessionResourceModifyListModInd)

	modifyItem := ngapType.PDUSessionResourceModifyItemModInd{}
	modifyItem.PDUSessionID.Value = pduSessionId
	modifyItem.PDUSessionResourceModifyIndicationTransfer = GetPDUSessionResourceModifyIndicationTransferWithDC(enableDC, mranDlTeid, sranDlTeid)

	ie.Value.PDUSessionResourceModifyListModInd.List = append(
		ie.Value.PDUSessionResourceModifyListModInd.List, modifyItem)

	indicationIEs.List = append(indicationIEs.List, ie)

	return pdu
}

func GetPDUSessionResourceModifyIndication(
	pduSessionId, amfUeNgapId, ranUeNgapId int64, enableDC bool, mranDlTeid, sranDlTeid string,
) ([]byte, error) {
	return ngap.Encoder(
		buildPDUSessionResourceModifyIndication(pduSessionId, amfUeNgapId, ranUeNgapId, enableDC, mranDlTeid, sranDlTeid))
}

// buildPathSwitchRequestTransferWithDC is like buildPathSwitchRequestTransfer but adds
// the new secondary RAN's downlink tunnel via AdditionalDLQosFlowPerTNLInformation in
// the transfer's IE Extensions. Used for Xn handover between an NR-DC master/secondary
// pair: the RAN initiating the switch becomes the new master (DLNGUUPTNLInformation),
// its former peer becomes the new secondary (the extension).
func buildPathSwitchRequestTransferWithDC(newMranDlTeid, newSranDlTeid string) ngapType.PathSwitchRequestTransfer {
	var data ngapType.PathSwitchRequestTransfer

	// DL NG-U UP TNL information (new master RAN)
	upTransportLayerInformation := &data.DLNGUUPTNLInformation
	upTransportLayerInformation.Present = ngapType.UPTransportLayerInformationPresentGTPTunnel
	upTransportLayerInformation.GTPTunnel = new(ngapType.GTPTunnel)
	upTransportLayerInformation.GTPTunnel.GTPTEID.Value = aper.OctetString(newMranDlTeid)
	upTransportLayerInformation.GTPTunnel.TransportLayerAddress = ngapConvert.IPAddressToNgap(IT_IP_2, "")

	// Qos Flow Accepted List
	qosFlowAcceptedList := &data.QosFlowAcceptedList
	qosFlowAcceptedItem := ngapType.QosFlowAcceptedItem{
		QosFlowIdentifier: ngapType.QosFlowIdentifier{
			Value: 1,
		},
	}
	qosFlowAcceptedList.List = append(qosFlowAcceptedList.List, qosFlowAcceptedItem)

	// Additional DL QoS Flow per TNL Information at IE Extensions (new secondary RAN)
	data.IEExtensions = new(ngapType.ProtocolExtensionContainerPathSwitchRequestTransferExtIEs)
	data.IEExtensions.List = append(data.IEExtensions.List, ngapType.PathSwitchRequestTransferExtIEs{
		Id: ngapType.ProtocolExtensionID{
			Value: ngapType.ProtocolIEIDAdditionalDLQosFlowPerTNLInformation,
		},
		Criticality: ngapType.Criticality{
			Value: ngapType.CriticalityPresentIgnore,
		},
		ExtensionValue: ngapType.PathSwitchRequestTransferExtIEsExtensionValue{
			Present: ngapType.PathSwitchRequestTransferExtIEsPresentAdditionalDLQosFlowPerTNLInformation,
			AdditionalDLQosFlowPerTNLInformation: &ngapType.QosFlowPerTNLInformationList{
				List: []ngapType.QosFlowPerTNLInformationItem{
					{
						QosFlowPerTNLInformation: ngapType.QosFlowPerTNLInformation{
							UPTransportLayerInformation: ngapType.UPTransportLayerInformation{
								Present: ngapType.UPTransportLayerInformationPresentGTPTunnel,
								GTPTunnel: &ngapType.GTPTunnel{
									GTPTEID: ngapType.GTPTEID{
										Value: aper.OctetString(newSranDlTeid),
									},
									TransportLayerAddress: ngapConvert.IPAddressToNgap(IT_IP, ""),
								},
							},
							AssociatedQosFlowList: ngapType.AssociatedQosFlowList{
								List: []ngapType.AssociatedQosFlowItem{
									{
										QosFlowIdentifier: ngapType.QosFlowIdentifier{
											Value: 1,
										},
									},
								},
							},
						},
					},
				},
			},
		},
	})

	return data
}

func GetPathSwitchRequestTransferWithDC(newMranDlTeid, newSranDlTeid string) []byte {
	data := buildPathSwitchRequestTransferWithDC(newMranDlTeid, newSranDlTeid)
	encodeData, err := aper.MarshalWithParams(data, "valueExt")
	if err != nil {
		fatal.Fatalf("aper MarshalWithParams error in GetPathSwitchRequestTransferWithDC: %+v", err)
	}
	return encodeData
}

func buildPathSwitchRequestWithDC(
	pduSessionId, amfUeNgapId, ranUeNgapId int64, newMranDlTeid, newSranDlTeid string,
) (pdu ngapType.NGAPPDU) {
	pdu.Present = ngapType.NGAPPDUPresentInitiatingMessage
	pdu.InitiatingMessage = new(ngapType.InitiatingMessage)

	initiatingMessage := pdu.InitiatingMessage
	initiatingMessage.ProcedureCode.Value = ngapType.ProcedureCodePathSwitchRequest
	initiatingMessage.Criticality.Value = ngapType.CriticalityPresentReject

	initiatingMessage.Value.Present = ngapType.InitiatingMessagePresentPathSwitchRequest
	initiatingMessage.Value.PathSwitchRequest = new(ngapType.PathSwitchRequest)

	pathSwitchRequest := initiatingMessage.Value.PathSwitchRequest
	pathSwitchRequestIEs := &pathSwitchRequest.ProtocolIEs

	// RAN UE NGAP ID
	ie := ngapType.PathSwitchRequestIEs{}
	ie.Id.Value = ngapType.ProtocolIEIDRANUENGAPID
	ie.Criticality.Value = ngapType.CriticalityPresentReject
	ie.Value.Present = ngapType.PathSwitchRequestIEsPresentRANUENGAPID
	ie.Value.RANUENGAPID = new(ngapType.RANUENGAPID)
	ie.Value.RANUENGAPID.Value = ranUeNgapId
	pathSwitchRequestIEs.List = append(pathSwitchRequestIEs.List, ie)

	// Source AMF UE NGAP ID
	ie = ngapType.PathSwitchRequestIEs{}
	ie.Id.Value = ngapType.ProtocolIEIDSourceAMFUENGAPID
	ie.Criticality.Value = ngapType.CriticalityPresentReject
	ie.Value.Present = ngapType.PathSwitchRequestIEsPresentSourceAMFUENGAPID
	ie.Value.SourceAMFUENGAPID = new(ngapType.AMFUENGAPID)
	ie.Value.SourceAMFUENGAPID.Value = amfUeNgapId
	pathSwitchRequestIEs.List = append(pathSwitchRequestIEs.List, ie)

	// User Location Information
	ie = ngapType.PathSwitchRequestIEs{}
	ie.Id.Value = ngapType.ProtocolIEIDUserLocationInformation
	ie.Criticality.Value = ngapType.CriticalityPresentIgnore
	ie.Value.Present = ngapType.PathSwitchRequestIEsPresentUserLocationInformation
	ie.Value.UserLocationInformation = new(ngapType.UserLocationInformation)

	userLocationInformation := ie.Value.UserLocationInformation
	userLocationInformation.Present = ngapType.UserLocationInformationPresentUserLocationInformationNR
	userLocationInformation.UserLocationInformationNR = new(ngapType.UserLocationInformationNR)

	userLocationInformationNR := userLocationInformation.UserLocationInformationNR
	userLocationInformationNR.NRCGI.PLMNIdentity.Value = aper.OctetString(PLMN_OCT)
	userLocationInformationNR.NRCGI.NRCellIdentity.Value = aper.BitString{
		Bytes:     []byte{0x00, 0x00, 0x00, 0x00, 0x20},
		BitLength: 36,
	}
	userLocationInformationNR.TAI.PLMNIdentity.Value = aper.OctetString(PLMN_OCT)
	userLocationInformationNR.TAI.TAC.Value = aper.OctetString("\x00\x00\x01")

	pathSwitchRequestIEs.List = append(pathSwitchRequestIEs.List, ie)

	// UE Security Capabilities
	ie = ngapType.PathSwitchRequestIEs{}
	ie.Id.Value = ngapType.ProtocolIEIDUESecurityCapabilities
	ie.Criticality.Value = ngapType.CriticalityPresentIgnore
	ie.Value.Present = ngapType.PathSwitchRequestIEsPresentUESecurityCapabilities
	ie.Value.UESecurityCapabilities = new(ngapType.UESecurityCapabilities)

	uESecurityCapabilities := ie.Value.UESecurityCapabilities
	uESecurityCapabilities.NRencryptionAlgorithms.Value = aper.BitString{Bytes: []byte{0xff, 0xff}, BitLength: 16}
	uESecurityCapabilities.NRintegrityProtectionAlgorithms.Value = aper.BitString{Bytes: []byte{0xff, 0xff}, BitLength: 16}
	uESecurityCapabilities.EUTRAencryptionAlgorithms.Value = aper.BitString{Bytes: []byte{0xff, 0xff}, BitLength: 16}
	uESecurityCapabilities.EUTRAintegrityProtectionAlgorithms.Value = aper.BitString{Bytes: []byte{0xff, 0xff}, BitLength: 16}

	pathSwitchRequestIEs.List = append(pathSwitchRequestIEs.List, ie)

	// PDU Session Resource to be Switched in Downlink List
	ie = ngapType.PathSwitchRequestIEs{}
	ie.Id.Value = ngapType.ProtocolIEIDPDUSessionResourceToBeSwitchedDLList
	ie.Criticality.Value = ngapType.CriticalityPresentReject
	ie.Value.Present = ngapType.PathSwitchRequestIEsPresentPDUSessionResourceToBeSwitchedDLList
	ie.Value.PDUSessionResourceToBeSwitchedDLList = new(ngapType.PDUSessionResourceToBeSwitchedDLList)

	pDUSessionResourceToBeSwitchedDLItem := ngapType.PDUSessionResourceToBeSwitchedDLItem{}
	pDUSessionResourceToBeSwitchedDLItem.PDUSessionID.Value = pduSessionId
	pDUSessionResourceToBeSwitchedDLItem.PathSwitchRequestTransfer = GetPathSwitchRequestTransferWithDC(newMranDlTeid, newSranDlTeid)

	ie.Value.PDUSessionResourceToBeSwitchedDLList.List = append(
		ie.Value.PDUSessionResourceToBeSwitchedDLList.List, pDUSessionResourceToBeSwitchedDLItem)

	pathSwitchRequestIEs.List = append(pathSwitchRequestIEs.List, ie)

	// note: unlike the plain GetPathSwitchRequest, this DC variant has no PDU Session
	// Resource Failed to Setup List IE at all (matching the reference test, which
	// leaves that IE commented out here rather than building-then-truncating it).

	return pdu
}

func GetPathSwitchRequestWithDC(
	pduSessionId, amfUeNgapId, ranUeNgapId int64, newMranDlTeid, newSranDlTeid string,
) ([]byte, error) {
	return ngap.Encoder(buildPathSwitchRequestWithDC(pduSessionId, amfUeNgapId, ranUeNgapId, newMranDlTeid, newSranDlTeid))
}
