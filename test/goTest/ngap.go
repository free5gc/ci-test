package test

// Hand-ported field-by-field from the old ngapType-based builders to the new
// ngap/ie + ngap/message API, rather than delegating to ngapTestpacket's
// Build* helpers: those helpers' sample fixtures embed different PLMN/TAC/IP
// defaults (e.g. NGSetupRequest's SD, HandoverRequestAcknowledgeTransfer's
// tunnel IP, HandoverNotify/HandoverRequired/PathSwitchRequest's PLMN/TAC) than
// this repo's environment expects, and several of test/goTest's callers don't
// override every field the samples leave stale. Hand-porting preserves the
// exact existing byte values with zero risk of silently changing what gets
// advertised to AMF.

import (
	"encoding/hex"
	"net"

	"github.com/calee0219/fatal"
	"github.com/free5gc/ngap/aper"
	"github.com/free5gc/ngap/ie"
	ngapMessage "github.com/free5gc/ngap/message"
)

// ipToTransportLayerAddress replaces ngapConvert.IPAddressToNgap(ip, "") for the
// IPv4-only case this file needs.
func ipToTransportLayerAddress(ipv4 string) *ie.TransportLayerAddress {
	return &ie.TransportLayerAddress{Value: aper.BitString{
		Bytes:     net.ParseIP(ipv4).To4(),
		BitLength: 32,
	}}
}

func gtpTunnel(ipv4, teid string) *ie.UPTransportLayerInformation {
	return &ie.UPTransportLayerInformation{Choice: &ie.GTPTunnel{
		TransportLayerAddress: ipToTransportLayerAddress(ipv4),
		GTPTEID:               &ie.GTPTEID{Value: aper.OctetString(teid)},
	}}
}

// pOctetString is a small helper for the *aper.OctetString struct fields that
// need a pointer to an inline-computed value.
func pOctetString(b []byte) *aper.OctetString {
	os := aper.OctetString(b)
	return &os
}

func GetNGSetupRequest(gnbId []byte, bitlength uint64, name string) ([]byte, error) {
	m := &ngapMessage.NGSetupRequest{
		GlobalRANNodeID: &ie.GlobalRANNodeID{Choice: &ie.GlobalGNBID{
			PLMNIdentity: &ie.PLMNIdentity{Value: aper.OctetString(PLMN_OCT)},
			GNBID: &ie.GNBID{Choice: &ie.GNBIDForGNBID{Value: aper.BitString{
				Bytes: gnbId, BitLength: bitlength,
			}}},
		}},
		RANNodeName: &ie.RANNodeName{Value: aper.PrintableString(name)},
		SupportedTAList: &ie.SupportedTAList{List: []ie.SupportedTAItem{{
			TAC: &ie.TAC{Value: aper.OctetString("\x00\x00\x01")},
			BroadcastPLMNList: &ie.BroadcastPLMNList{List: []ie.BroadcastPLMNItem{{
				PLMNIdentity: &ie.PLMNIdentity{Value: aper.OctetString(PLMN_OCT)},
				TAISliceSupportList: &ie.SliceSupportList{List: []ie.SliceSupportItem{{
					SNSSAI: &ie.SNSSAI{
						SST: &ie.SST{Value: aper.OctetString(SST_OCT)},
						SD:  &ie.SD{Value: aper.OctetString(SD_OCT)},
					},
				}}},
			}}},
		}}},
		DefaultPagingDRX: &ie.PagingDRX{Value: ie.PagingDRXPresentV128},
	}
	return m.MarshalBinary()
}

func nrUserLocationInformation() *ie.UserLocationInformation {
	return &ie.UserLocationInformation{Choice: &ie.UserLocationInformationNR{
		NRCGI: &ie.NRCGI{
			PLMNIdentity:   &ie.PLMNIdentity{Value: aper.OctetString(PLMN_OCT)},
			NRCellIdentity: &ie.NRCellIdentity{Value: aper.BitString{Bytes: []byte{0x00, 0x00, 0x00, 0x00, 0x10}, BitLength: 36}},
		},
		TAI: &ie.TAI{
			PLMNIdentity: &ie.PLMNIdentity{Value: aper.OctetString(PLMN_OCT)},
			TAC:          &ie.TAC{Value: aper.OctetString("\x00\x00\x01")},
		},
	}}
}

func GetInitialUEMessage(ranUeNgapID int64, nasPdu []byte, fiveGSTmsi string) ([]byte, error) {
	m := &ngapMessage.InitialUEMessage{
		RANUENGAPID:             &ie.RANUENGAPID{Value: ranUeNgapID},
		NASPDU:                  &ie.NASPDU{Value: aper.OctetString(nasPdu)},
		UserLocationInformation: nrUserLocationInformation(),
		RRCEstablishmentCause:   &ie.RRCEstablishmentCause{Value: ie.RRCEstablishmentCausePresentMtAccess},
		UEContextRequest:        &ie.UEContextRequest{Value: ie.UEContextRequestPresentRequested},
	}

	if fiveGSTmsi != "" {
		amfSetID, err := hex.DecodeString(fiveGSTmsi[:4])
		if err != nil {
			fatal.Fatalf("DecodeString error in GetInitialUEMessage: %+v", err)
		}
		amfPointer, err := hex.DecodeString(fiveGSTmsi[2:4])
		if err != nil {
			fatal.Fatalf("DecodeString error in GetInitialUEMessage: %+v", err)
		}
		tmsi, err := hex.DecodeString(fiveGSTmsi[4:])
		if err != nil {
			fatal.Fatalf("DecodeString error in GetInitialUEMessage: %+v", err)
		}
		m.FiveGSTMSI = &ie.FiveGSTMSI{
			AMFSetID:   &ie.AMFSetID{Value: aper.BitString{Bytes: amfSetID, BitLength: 10}},
			AMFPointer: &ie.AMFPointer{Value: aper.BitString{Bytes: amfPointer, BitLength: 6}},
			FiveGTMSI:  &ie.FiveGTMSI{Value: aper.OctetString(tmsi)},
		}
	}

	return m.MarshalBinary()
}

func GetUplinkNASTransport(amfUeNgapID, ranUeNgapID int64, nasPdu []byte) ([]byte, error) {
	m := &ngapMessage.UplinkNASTransport{
		AMFUENGAPID:             &ie.AMFUENGAPID{Value: amfUeNgapID},
		RANUENGAPID:             &ie.RANUENGAPID{Value: ranUeNgapID},
		NASPDU:                  &ie.NASPDU{Value: aper.OctetString(nasPdu)},
		UserLocationInformation: nrUserLocationInformation(),
	}
	return m.MarshalBinary()
}

func GetInitialContextSetupResponse(amfUeNgapID int64, ranUeNgapID int64) ([]byte, error) {
	m := &ngapMessage.InitialContextSetupResponse{
		AMFUENGAPID: &ie.AMFUENGAPID{Value: amfUeNgapID},
		RANUENGAPID: &ie.RANUENGAPID{Value: ranUeNgapID},
	}
	return m.MarshalBinary()
}

func buildPDUSessionResourceSetupResponseTransfer(ipv4 string) *ie.PDUSessionResourceSetupResponseTransfer {
	return &ie.PDUSessionResourceSetupResponseTransfer{
		DLQosFlowPerTNLInformation: &ie.QosFlowPerTNLInformation{
			UPTransportLayerInformation: gtpTunnel(ipv4, "\x00\x00\x00\x01"),
			AssociatedQosFlowList: &ie.AssociatedQosFlowList{List: []ie.AssociatedQosFlowItem{{
				QosFlowIdentifier: &ie.QosFlowIdentifier{Value: 1},
			}}},
		},
	}
}

func GetPDUSessionResourceSetupResponseTransfer(ipv4 string) []byte {
	encodeData, err := ie.MarshalBinary(buildPDUSessionResourceSetupResponseTransfer(ipv4))
	if err != nil {
		fatal.Fatalf("ie.MarshalBinary error in GetPDUSessionResourceSetupResponseTransfer: %+v", err)
	}
	return encodeData
}

func GetPDUSessionResourceSetupResponse(pduSessionId int64, amfUeNgapID int64, ranUeNgapID int64, ipv4 string) ([]byte, error) {
	transfer := aper.OctetString(GetPDUSessionResourceSetupResponseTransfer(ipv4))
	m := &ngapMessage.PDUSessionResourceSetupResponse{
		AMFUENGAPID: &ie.AMFUENGAPID{Value: amfUeNgapID},
		RANUENGAPID: &ie.RANUENGAPID{Value: ranUeNgapID},
		PDUSessionResourceSetupListSURes: &ie.PDUSessionResourceSetupListSURes{List: []ie.PDUSessionResourceSetupItemSURes{{
			PDUSessionID:                            &ie.PDUSessionID{Value: pduSessionId},
			PDUSessionResourceSetupResponseTransfer: &transfer,
		}}},
		// Note: the "PDU Session Resource Failed to Setup List" IE is deliberately
		// omitted, matching the reference test which leaves it commented out
		// since no PDU session in this scenario actually fails to set up.
	}
	return m.MarshalBinary()
}

func GetUEContextReleaseComplete(amfUeNgapID, ranUeNgapID int64, pduSessionIDList []int64) ([]byte, error) {
	m := &ngapMessage.UEContextReleaseComplete{
		AMFUENGAPID:             &ie.AMFUENGAPID{Value: amfUeNgapID},
		RANUENGAPID:             &ie.RANUENGAPID{Value: ranUeNgapID},
		UserLocationInformation: nrUserLocationInformation(),
	}
	if pduSessionIDList != nil {
		list := &ie.PDUSessionResourceListCxtRelCpl{}
		for _, id := range pduSessionIDList {
			list.List = append(list.List, ie.PDUSessionResourceItemCxtRelCpl{PDUSessionID: &ie.PDUSessionID{Value: id}})
		}
		m.PDUSessionResourceListCxtRelCpl = list
	}
	return m.MarshalBinary()
}

func GetPDUSessionResourceReleaseResponseTransfer() []byte {
	encodeData, err := ie.MarshalBinary(&ie.PDUSessionResourceReleaseResponseTransfer{})
	if err != nil {
		fatal.Fatalf("ie.MarshalBinary error in GetPDUSessionResourceReleaseResponseTransfer: %+v", err)
	}
	return encodeData
}

func GetPDUSessionResourceReleaseResponse(amfUeNgapID, ranUeNgapID int64) ([]byte, error) {
	transfer := aper.OctetString(GetPDUSessionResourceReleaseResponseTransfer())
	m := &ngapMessage.PDUSessionResourceReleaseResponse{
		AMFUENGAPID: &ie.AMFUENGAPID{Value: amfUeNgapID},
		RANUENGAPID: &ie.RANUENGAPID{Value: ranUeNgapID},
		PDUSessionResourceReleasedListRelRes: &ie.PDUSessionResourceReleasedListRelRes{List: []ie.PDUSessionResourceReleasedItemRelRes{{
			PDUSessionID: &ie.PDUSessionID{Value: 10},
			PDUSessionResourceReleaseResponseTransfer: &transfer,
		}}},
	}
	return m.MarshalBinary()
}

func GetUEContextReleaseRequest(amfUeNgapID, ranUeNgapID int64, pduSessionIDList []int64) ([]byte, error) {
	m := &ngapMessage.UEContextReleaseRequest{
		AMFUENGAPID: &ie.AMFUENGAPID{Value: amfUeNgapID},
		RANUENGAPID: &ie.RANUENGAPID{Value: ranUeNgapID},
		Cause: &ie.Cause{Choice: &ie.CauseRadioNetwork{
			Value: ie.CauseRadioNetworkPresentTxnrelocoverallExpiry,
		}},
	}
	if pduSessionIDList != nil {
		list := &ie.PDUSessionResourceListCxtRelReq{}
		for _, id := range pduSessionIDList {
			list.List = append(list.List, ie.PDUSessionResourceItemCxtRelReq{PDUSessionID: &ie.PDUSessionID{Value: id}})
		}
		m.PDUSessionResourceListCxtRelReq = list
	}
	return m.MarshalBinary()
}

func GetInitialContextSetupResponseForServiceRequest(amfUeNgapID, ranUeNgapID int64, ipv4 string) ([]byte, error) {
	transfer := aper.OctetString(GetPDUSessionResourceSetupResponseTransfer(ipv4))
	m := &ngapMessage.InitialContextSetupResponse{
		AMFUENGAPID: &ie.AMFUENGAPID{Value: amfUeNgapID},
		RANUENGAPID: &ie.RANUENGAPID{Value: ranUeNgapID},
		PDUSessionResourceSetupListCxtRes: &ie.PDUSessionResourceSetupListCxtRes{List: []ie.PDUSessionResourceSetupItemCxtRes{{
			PDUSessionID:                            &ie.PDUSessionID{Value: 10},
			PDUSessionResourceSetupResponseTransfer: &transfer,
		}}},
	}
	return m.MarshalBinary()
}

func GetHandoverRequestAcknowledgeTransfer() []byte {
	data := &ie.HandoverRequestAcknowledgeTransfer{
		DLNGUUPTNLInformation:        gtpTunnel(IT_IP, "\x00\x00\x00\x01"),
		DLForwardingUPTNLInformation: gtpTunnel(IT_IP, "\x00\x00\x00\x02"),
		QosFlowSetupResponseList: &ie.QosFlowListWithDataForwarding{List: []ie.QosFlowItemWithDataForwarding{{
			QosFlowIdentifier: &ie.QosFlowIdentifier{Value: 9},
		}}},
	}
	encodeData, err := ie.MarshalBinary(data)
	if err != nil {
		fatal.Fatalf("ie.MarshalBinary error in GetHandoverRequestAcknowledgeTransfer: %+v", err)
	}
	return encodeData
}

func GetHandoverRequestAcknowledge(amfUeNgapID, ranUeNgapID int64) ([]byte, error) {
	transfer := aper.OctetString(GetHandoverRequestAcknowledgeTransfer())
	m := &ngapMessage.HandoverRequestAcknowledge{
		AMFUENGAPID: &ie.AMFUENGAPID{Value: amfUeNgapID},
		RANUENGAPID: &ie.RANUENGAPID{Value: ranUeNgapID},
		PDUSessionResourceAdmittedList: &ie.PDUSessionResourceAdmittedList{List: []ie.PDUSessionResourceAdmittedItem{{
			PDUSessionID:                       &ie.PDUSessionID{Value: 10},
			HandoverRequestAcknowledgeTransfer: &transfer,
		}}},
		TargetToSourceTransparentContainer: &ie.TargetToSourceTransparentContainer{
			Value: aper.OctetString("\x00\x01\x00\x00"),
		},
	}
	return m.MarshalBinary()
}

func GetHandoverNotify(amfUeNgapID, ranUeNgapID int64) ([]byte, error) {
	m := &ngapMessage.HandoverNotify{
		AMFUENGAPID: &ie.AMFUENGAPID{Value: amfUeNgapID},
		RANUENGAPID: &ie.RANUENGAPID{Value: ranUeNgapID},
		UserLocationInformation: &ie.UserLocationInformation{Choice: &ie.UserLocationInformationEUTRA{
			TAI: &ie.TAI{
				PLMNIdentity: &ie.PLMNIdentity{Value: aper.OctetString(PLMN_OCT)},
				TAC:          &ie.TAC{Value: aper.OctetString("\x00\x00\x01")},
			},
			EUTRACGI: &ie.EUTRACGI{
				PLMNIdentity: &ie.PLMNIdentity{Value: aper.OctetString(PLMN_OCT)},
				EUTRACellIdentity: &ie.EUTRACellIdentity{Value: aper.BitString{
					Bytes: []byte{0x24, 0x16, 0x08, 0xFF}, BitLength: 28,
				}},
			},
		}},
	}
	return m.MarshalBinary()
}

func GetPDUSessionResourceSetupResponseForPaging(amfUeNgapID, ranUeNgapID int64, ipv4 string) ([]byte, error) {
	transfer := aper.OctetString(GetPDUSessionResourceSetupResponseTransfer(ipv4))
	m := &ngapMessage.PDUSessionResourceSetupResponse{
		AMFUENGAPID: &ie.AMFUENGAPID{Value: amfUeNgapID},
		RANUENGAPID: &ie.RANUENGAPID{Value: ranUeNgapID},
		PDUSessionResourceSetupListSURes: &ie.PDUSessionResourceSetupListSURes{List: []ie.PDUSessionResourceSetupItemSURes{{
			PDUSessionID:                            &ie.PDUSessionID{Value: 10},
			PDUSessionResourceSetupResponseTransfer: &transfer,
		}}},
		PDUSessionResourceFailedToSetupListSURes: &ie.PDUSessionResourceFailedToSetupListSURes{},
	}
	return m.MarshalBinary()
}

func GetHandoverRequiredTransfer() []byte {
	data := &ie.HandoverRequiredTransfer{
		DirectForwardingPathAvailability: &ie.DirectForwardingPathAvailability{
			Value: ie.DirectForwardingPathAvailabilityPresentDirectPathAvailable,
		},
	}
	encodeData, err := ie.MarshalBinary(data)
	if err != nil {
		fatal.Fatalf("ie.MarshalBinary error in GetHandoverRequiredTransfer: %+v", err)
	}
	return encodeData
}

func GetSourceToTargetTransparentTransfer(targetGNBID []byte, targetCellID []byte) []byte {
	targetCell := append(append([]byte(nil), targetGNBID...), targetCellID...)
	data := &ie.SourceNGRANNodeToTargetNGRANNodeTransparentContainer{
		RRCContainer: &ie.RRCContainer{Value: aper.OctetString("\x00\x00\x11")},
		PDUSessionResourceInformationList: &ie.PDUSessionResourceInformationList{List: []ie.PDUSessionResourceInformationItem{{
			PDUSessionID: &ie.PDUSessionID{Value: 10},
			QosFlowInformationList: &ie.QosFlowInformationList{List: []ie.QosFlowInformationItem{{
				QosFlowIdentifier: &ie.QosFlowIdentifier{Value: 1},
			}}},
		}}},
		TargetCellID: &ie.NGRANCGI{Choice: &ie.NRCGI{
			PLMNIdentity:   &ie.PLMNIdentity{Value: aper.OctetString(PLMN_OCT)},
			NRCellIdentity: &ie.NRCellIdentity{Value: aper.BitString{Bytes: targetCell, BitLength: 36}},
		}},
		UEHistoryInformation: &ie.UEHistoryInformation{List: []ie.LastVisitedCellItem{{
			LastVisitedCellInformation: &ie.LastVisitedCellInformation{Choice: &ie.LastVisitedNGRANCellInformation{
				GlobalCellID: &ie.NGRANCGI{Choice: &ie.NRCGI{
					PLMNIdentity:   &ie.PLMNIdentity{Value: aper.OctetString(PLMN_OCT)},
					NRCellIdentity: &ie.NRCellIdentity{Value: aper.BitString{Bytes: []byte{0x00, 0x00, 0x00, 0x00, 0x10}, BitLength: 36}},
				}},
				CellType:           &ie.CellType{CellSize: &ie.CellSize{Value: ie.CellSizePresentVerysmall}},
				TimeUEStayedInCell: &ie.TimeUEStayedInCell{Value: 10},
			}},
		}}},
	}
	encodeData, err := ie.MarshalBinary(data)
	if err != nil {
		fatal.Fatalf("ie.MarshalBinary error in GetSourceToTargetTransparentTransfer: %+v", err)
	}
	return encodeData
}

func GetHandoverRequired(amfUeNgapID, ranUeNgapID int64, targetGNBID []byte, targetCellID []byte) ([]byte, error) {
	m := &ngapMessage.HandoverRequired{
		AMFUENGAPID:  &ie.AMFUENGAPID{Value: amfUeNgapID},
		RANUENGAPID:  &ie.RANUENGAPID{Value: ranUeNgapID},
		HandoverType: &ie.HandoverType{Value: ie.HandoverTypePresentIntra5gs},
		Cause: &ie.Cause{Choice: &ie.CauseRadioNetwork{
			Value: ie.CauseRadioNetworkPresentHandoverDesirableForRadioReason,
		}},
		TargetID: &ie.TargetID{Choice: &ie.TargetRANNodeID{
			GlobalRANNodeID: &ie.GlobalRANNodeID{Choice: &ie.GlobalGNBID{
				PLMNIdentity: &ie.PLMNIdentity{Value: aper.OctetString(PLMN_OCT)},
				GNBID: &ie.GNBID{Choice: &ie.GNBIDForGNBID{Value: aper.BitString{
					Bytes: targetGNBID, BitLength: uint64(len(targetGNBID) * 8),
				}}},
			}},
			SelectedTAI: &ie.TAI{
				PLMNIdentity: &ie.PLMNIdentity{Value: aper.OctetString(PLMN_OCT)},
				TAC:          &ie.TAC{Value: aper.OctetString("\x00\x00\x01")},
			},
		}},
		PDUSessionResourceListHORqd: &ie.PDUSessionResourceListHORqd{List: []ie.PDUSessionResourceItemHORqd{{
			PDUSessionID:             &ie.PDUSessionID{Value: 10},
			HandoverRequiredTransfer: pOctetString(GetHandoverRequiredTransfer()),
		}}},
		SourceToTargetTransparentContainer: &ie.SourceToTargetTransparentContainer{
			Value: aper.OctetString(GetSourceToTargetTransparentTransfer(targetGNBID, targetCellID)),
		},
	}
	return m.MarshalBinary()
}

func GetPathSwitchRequestTransfer() []byte {
	data := &ie.PathSwitchRequestTransfer{
		DLNGUUPTNLInformation: gtpTunnel(IT_IP, "\x00\x00\x00\x02"),
		QosFlowAcceptedList: &ie.QosFlowAcceptedList{List: []ie.QosFlowAcceptedItem{{
			QosFlowIdentifier: &ie.QosFlowIdentifier{Value: 1},
		}}},
	}
	encodeData, err := ie.MarshalBinary(data)
	if err != nil {
		fatal.Fatalf("ie.MarshalBinary error in GetPathSwitchRequestTransfer: %+v", err)
	}
	return encodeData
}

func GetPathSwitchRequestSetupFailedTransfer() []byte {
	data := &ie.PathSwitchRequestSetupFailedTransfer{
		Cause: &ie.Cause{Choice: &ie.CauseTransport{
			Value: ie.CauseTransportPresentTransportResourceUnavailable,
		}},
	}
	encodeData, err := ie.MarshalBinary(data)
	if err != nil {
		fatal.Fatalf("ie.MarshalBinary error in GetPathSwitchRequestSetupFailedTransfer: %+v", err)
	}
	return encodeData
}

// GetPathSwitchRequest matches the reference test's own GetPathSwitchRequest,
// which excludes the PDU Session Resource Failed to Setup List IE since no PDU
// session in this test scenario actually fails to set up (the old code built
// that IE and then truncated it back off before encoding; this just never
// builds it, which is behaviorally identical).
func GetPathSwitchRequest(amfUeNgapID, ranUeNgapID int64) ([]byte, error) {
	m := &ngapMessage.PathSwitchRequest{
		RANUENGAPID:             &ie.RANUENGAPID{Value: ranUeNgapID},
		SourceAMFUENGAPID:       &ie.AMFUENGAPID{Value: amfUeNgapID},
		UserLocationInformation: nrUserLocationInformation(),
		UESecurityCapabilities: &ie.UESecurityCapabilities{
			NRencryptionAlgorithms:             &ie.NRencryptionAlgorithms{Value: aper.BitString{Bytes: []byte{0xff, 0xff}, BitLength: 16}},
			NRintegrityProtectionAlgorithms:    &ie.NRintegrityProtectionAlgorithms{Value: aper.BitString{Bytes: []byte{0xff, 0xff}, BitLength: 16}},
			EUTRAencryptionAlgorithms:          &ie.EUTRAencryptionAlgorithms{Value: aper.BitString{Bytes: []byte{0xff, 0xff}, BitLength: 16}},
			EUTRAintegrityProtectionAlgorithms: &ie.EUTRAintegrityProtectionAlgorithms{Value: aper.BitString{Bytes: []byte{0xff, 0xff}, BitLength: 16}},
		},
		PDUSessionResourceToBeSwitchedDLList: &ie.PDUSessionResourceToBeSwitchedDLList{
			List: []ie.PDUSessionResourceToBeSwitchedDLItem{{
				PDUSessionID:              &ie.PDUSessionID{Value: 10},
				PathSwitchRequestTransfer: pOctetString(GetPathSwitchRequestTransfer()),
			}},
		},
	}
	return m.MarshalBinary()
}

// ---------------------------------------------------------------------------
// Dual-connectivity (DC) variants. These add a secondary RAN's downlink QoS
// flow mapping via AdditionalDLQosFlowPerTNLInformation, for NR-DC tests where
// a single PDU session's downlink traffic is delivered through both a master
// and a secondary RAN simultaneously.
// ---------------------------------------------------------------------------

func buildQosFlowPerTNLInformation(ipv4, teid string) *ie.QosFlowPerTNLInformation {
	return &ie.QosFlowPerTNLInformation{
		UPTransportLayerInformation: gtpTunnel(ipv4, teid),
		AssociatedQosFlowList: &ie.AssociatedQosFlowList{List: []ie.AssociatedQosFlowItem{{
			QosFlowIdentifier: &ie.QosFlowIdentifier{Value: 1},
		}}},
	}
}

func GetPDUSessionResourceSetupResponseTransferWithDC(mranDlTeid, sranDlTeid string) []byte {
	data := &ie.PDUSessionResourceSetupResponseTransfer{
		DLQosFlowPerTNLInformation: buildQosFlowPerTNLInformation(IT_IP, mranDlTeid),
		AdditionalDLQosFlowPerTNLInformation: &ie.QosFlowPerTNLInformationList{List: []ie.QosFlowPerTNLInformationItem{{
			QosFlowPerTNLInformation: buildQosFlowPerTNLInformation(IT_IP_2, sranDlTeid),
		}}},
	}
	encodeData, err := ie.MarshalBinary(data)
	if err != nil {
		fatal.Fatalf("ie.MarshalBinary error in GetPDUSessionResourceSetupResponseTransferWithDC: %+v", err)
	}
	return encodeData
}

func GetPDUSessionResourceSetupResponseWithDC(
	pduSessionId, amfUeNgapId, ranUeNgapId int64, mranDlTeid, sranDlTeid string,
) ([]byte, error) {
	transfer := aper.OctetString(GetPDUSessionResourceSetupResponseTransferWithDC(mranDlTeid, sranDlTeid))
	m := &ngapMessage.PDUSessionResourceSetupResponse{
		AMFUENGAPID: &ie.AMFUENGAPID{Value: amfUeNgapId},
		RANUENGAPID: &ie.RANUENGAPID{Value: ranUeNgapId},
		PDUSessionResourceSetupListSURes: &ie.PDUSessionResourceSetupListSURes{List: []ie.PDUSessionResourceSetupItemSURes{{
			PDUSessionID:                            &ie.PDUSessionID{Value: pduSessionId},
			PDUSessionResourceSetupResponseTransfer: &transfer,
		}}},
	}
	return m.MarshalBinary()
}

func GetPDUSessionResourceModifyIndicationTransferWithDC(enableDC bool, mranDlTeid, sranDlTeid string) []byte {
	data := &ie.PDUSessionResourceModifyIndicationTransfer{
		DLQosFlowPerTNLInformation: buildQosFlowPerTNLInformation(IT_IP, mranDlTeid),
	}
	if enableDC {
		data.AdditionalDLQosFlowPerTNLInformation = &ie.QosFlowPerTNLInformationList{List: []ie.QosFlowPerTNLInformationItem{{
			QosFlowPerTNLInformation: buildQosFlowPerTNLInformation(IT_IP_2, sranDlTeid),
		}}}
	}
	encodeData, err := ie.MarshalBinary(data)
	if err != nil {
		fatal.Fatalf("ie.MarshalBinary error in GetPDUSessionResourceModifyIndicationTransferWithDC: %+v", err)
	}
	return encodeData
}

func GetPDUSessionResourceModifyIndication(
	pduSessionId, amfUeNgapId, ranUeNgapId int64, enableDC bool, mranDlTeid, sranDlTeid string,
) ([]byte, error) {
	transfer := aper.OctetString(GetPDUSessionResourceModifyIndicationTransferWithDC(enableDC, mranDlTeid, sranDlTeid))
	m := &ngapMessage.PDUSessionResourceModifyIndication{
		AMFUENGAPID: &ie.AMFUENGAPID{Value: amfUeNgapId},
		RANUENGAPID: &ie.RANUENGAPID{Value: ranUeNgapId},
		PDUSessionResourceModifyListModInd: &ie.PDUSessionResourceModifyListModInd{List: []ie.PDUSessionResourceModifyItemModInd{{
			PDUSessionID: &ie.PDUSessionID{Value: pduSessionId},
			PDUSessionResourceModifyIndicationTransfer: &transfer,
		}}},
	}
	return m.MarshalBinary()
}

func GetPathSwitchRequestTransferWithDC(newMranDlTeid, newSranDlTeid string) []byte {
	data := &ie.PathSwitchRequestTransfer{
		DLNGUUPTNLInformation: gtpTunnel(IT_IP_2, newMranDlTeid),
		QosFlowAcceptedList: &ie.QosFlowAcceptedList{List: []ie.QosFlowAcceptedItem{{
			QosFlowIdentifier: &ie.QosFlowIdentifier{Value: 1},
		}}},
		IEExtensions: &ie.ProtocolExtensionContainerPathSwitchRequestTransferExtIEs{
			List: []ie.PathSwitchRequestTransferExtIEs{{
				Id:          &ie.ProtocolExtensionID{Value: ie.ProtocolIEIDAdditionalDLQosFlowPerTNLInformation},
				Criticality: &ie.Criticality{Value: ie.CriticalityPresentIgnore},
				AdditionalDLQosFlowPerTNLInformation: &ie.QosFlowPerTNLInformationList{List: []ie.QosFlowPerTNLInformationItem{{
					QosFlowPerTNLInformation: buildQosFlowPerTNLInformation(IT_IP, newSranDlTeid),
				}}},
			}},
		},
	}
	encodeData, err := ie.MarshalBinary(data)
	if err != nil {
		fatal.Fatalf("ie.MarshalBinary error in GetPathSwitchRequestTransferWithDC: %+v", err)
	}
	return encodeData
}

// GetPathSwitchRequestWithDC has no PDU Session Resource Failed to Setup List
// IE at all (matching the original, which built the PathSwitchRequest without
// that IE for this DC variant rather than building-then-truncating it like the
// plain GetPathSwitchRequest does).
func GetPathSwitchRequestWithDC(
	pduSessionId, amfUeNgapId, ranUeNgapId int64, newMranDlTeid, newSranDlTeid string,
) ([]byte, error) {
	m := &ngapMessage.PathSwitchRequest{
		RANUENGAPID:             &ie.RANUENGAPID{Value: ranUeNgapId},
		SourceAMFUENGAPID:       &ie.AMFUENGAPID{Value: amfUeNgapId},
		UserLocationInformation: nrUserLocationInformation(),
		UESecurityCapabilities: &ie.UESecurityCapabilities{
			NRencryptionAlgorithms:             &ie.NRencryptionAlgorithms{Value: aper.BitString{Bytes: []byte{0xff, 0xff}, BitLength: 16}},
			NRintegrityProtectionAlgorithms:    &ie.NRintegrityProtectionAlgorithms{Value: aper.BitString{Bytes: []byte{0xff, 0xff}, BitLength: 16}},
			EUTRAencryptionAlgorithms:          &ie.EUTRAencryptionAlgorithms{Value: aper.BitString{Bytes: []byte{0xff, 0xff}, BitLength: 16}},
			EUTRAintegrityProtectionAlgorithms: &ie.EUTRAintegrityProtectionAlgorithms{Value: aper.BitString{Bytes: []byte{0xff, 0xff}, BitLength: 16}},
		},
		PDUSessionResourceToBeSwitchedDLList: &ie.PDUSessionResourceToBeSwitchedDLList{
			List: []ie.PDUSessionResourceToBeSwitchedDLItem{{
				PDUSessionID:              &ie.PDUSessionID{Value: pduSessionId},
				PathSwitchRequestTransfer: pOctetString(GetPathSwitchRequestTransferWithDC(newMranDlTeid, newSranDlTeid)),
			}},
		},
	}
	return m.MarshalBinary()
}
