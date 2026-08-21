package test

import (
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"net"

	"github.com/free5gc/nas/ie"
	"github.com/free5gc/nas/message"
	ngapMessage "github.com/free5gc/ngap/message"
	"github.com/free5gc/openapi/models"
)

const (
	PDUSesModiReq    string = "PDU Session Modification Request"
	PDUSesModiCmp    string = "PDU Session Modification Complete"
	PDUSesModiCmdRej string = "PDU Session Modification Command Reject"
	PDUSesRelReq     string = "PDU Session Release Request"
	PDUSesRelCmp     string = "PDU Session Release Complete"
	PDUSesRelRej     string = "PDU Session Release Reject"
	PDUSesAuthCmp    string = "PDU Session Authentication Complete"
)

// NewSecCtx builds the security context the new nas API needs, borrowing the
// UE's own counters rather than copying them: message.Marshal and message.Parse
// advance the counter they are given, and that state has to stay in the
// RanUeContext for the rest of the flow. Anything derived from the UE (keys,
// algorithms, bearer) is read at call time, so this is safe to build fresh for
// every message -- and it has to be, because the keys only exist after
// DerivateAlgKey has run.
func (ue *RanUeContext) NewSecCtx() *message.SecCtx {
	secCtx := message.NewSecCtx(
		message.UESide,
		ue.GetBearerType(),
		ue.CipheringAlg,
		ue.IntegrityAlg,
		ue.KnasEnc[:],
		ue.KnasInt[:],
	)
	secCtx.UplinkCount = &ue.ULCount
	secCtx.DownlinkCount = &ue.DLCount
	return secCtx
}

// NASEncode serializes a NAS message, applying security when a context is
// available. The security header type used to be carried on nas.Message; the
// new API takes it as an explicit argument to message.Marshal.
func NASEncode(ue *RanUeContext, msg message.Message, securityHeaderType message.SecHdrType,
	securityContextAvailable bool, newSecurityContext bool,
) ([]byte, error) {
	if ue == nil {
		return nil, fmt.Errorf("ue is nil")
	}
	if msg == nil {
		return nil, fmt.Errorf("Nas Message is empty")
	}

	if !securityContextAvailable {
		return message.Marshal(msg, nil, message.SecHdrTypePlainNas)
	}

	if newSecurityContext {
		// message.Marshal only resets the direction it is about to use, so
		// reset both here to keep the previous behaviour.
		ue.ULCount.Set(0, 0)
		ue.DLCount.Set(0, 0)
	}

	return message.Marshal(msg, ue.NewSecCtx(), securityHeaderType)
}

// NASEnvelopeEncode is NASEncode wrapped in the TS 24.502 9.4 envelope used
// over non-3GPP access.
func NASEnvelopeEncode(ue *RanUeContext, msg message.Message, securityHeaderType message.SecHdrType,
	securityContextAvailable bool, newSecurityContext bool,
) ([]byte, error) {
	payload, err := NASEncode(ue, msg, securityHeaderType, securityContextAvailable, newSecurityContext)
	if err != nil {
		return nil, err
	}
	return encapNasMsgToEnvelope(payload), nil
}

// NASDecode parses a received NAS message, verifying and decrypting it when the
// UE has a security context.
//
// message.Parse reports a MAC mismatch by returning both the parsed message and
// a *message.Error, and it rolls the counter back itself. The previous
// implementation only logged the mismatch and carried on, so keep that: some
// test flows exercise cases where the MAC is not expected to match yet.
func NASDecode(ue *RanUeContext, securityHeaderType message.SecHdrType, payload []byte) (message.Message, error) {
	if ue == nil {
		return nil, fmt.Errorf("ue is nil")
	}
	if payload == nil {
		return nil, fmt.Errorf("Nas payload is empty")
	}

	if securityHeaderType == message.SecHdrTypePlainNas {
		return message.Parse(payload, nil)
	}

	msg, err := message.Parse(payload, ue.NewSecCtx())

	var nasErr *message.Error
	if errors.As(err, &nasErr) && nasErr.MACFailure != nil {
		fmt.Printf("NAS MAC verification failed(0x%x != 0x%x)\n",
			nasErr.MACFailure.Expected, nasErr.MACFailure.Received)
		return msg, nil
	}

	return msg, err
}

// encapNasMsgToEnvelope wraps a NAS message in a NAS message envelope (Length | NAS
// Message) as defined in TS 24.502 9.4, used to transport NAS over the non-3GPP access
// between the UE and N3IWF/TNGF (TS 24.502 8.2.4).
func encapNasMsgToEnvelope(nasPDU []byte) []byte {
	nasEnv := make([]byte, 2)
	binary.BigEndian.PutUint16(nasEnv, uint16(len(nasPDU)))
	nasEnv = append(nasEnv, nasPDU...)
	return nasEnv
}

// DecapNasPduFromEnvelope strips the NAS message envelope (TS 24.502 9.4) and returns
// the inner NAS message.
func DecapNasPduFromEnvelope(envelop []byte) ([]byte, int, error) {
	if uint16(len(envelop)) < 2 {
		return envelop, 0, fmt.Errorf("NAS message envelope is less than 2 bytes")
	}
	nasLen := binary.BigEndian.Uint16(envelop[:2])
	if uint16(len(envelop)) < 2+nasLen {
		return envelop, 0, fmt.Errorf("NAS message envelope is less than the sum of 2 and naslen")
	}
	nasMsg := make([]byte, nasLen)
	copy(nasMsg, envelop[2:2+nasLen])

	return nasMsg, int(nasLen), nil
}

// EncodeNasPduWithSecurity takes an already-built plain NAS PDU (as produced by
// one of the GetXxx message builders below) and wraps it in a security
// envelope. The new API works on message.Message rather than raw bytes, so the
// PDU is parsed back first; that round trip is byte-exact for every message
// the builders below produce.
func EncodeNasPduWithSecurity(ue *RanUeContext, pdu []byte, securityHeaderType message.SecHdrType,
	securityContextAvailable, newSecurityContext bool,
) ([]byte, error) {
	m, err := message.ParseGMM(pdu)
	if err != nil {
		return nil, err
	}
	return NASEncode(ue, m, securityHeaderType, securityContextAvailable, newSecurityContext)
}

// EncodeNasPduInEnvelopeWithSecurity is like EncodeNasPduWithSecurity but wraps the
// result in a NAS message envelope (see NASEnvelopeEncode), for NAS sent over the
// N3IWF/TNGF NAS TCP connection.
func EncodeNasPduInEnvelopeWithSecurity(ue *RanUeContext, pdu []byte, securityHeaderType message.SecHdrType,
	securityContextAvailable, newSecurityContext bool,
) ([]byte, error) {
	m, err := message.ParseGMM(pdu)
	if err != nil {
		return nil, err
	}
	return NASEnvelopeEncode(ue, m, securityHeaderType, securityContextAvailable, newSecurityContext)
}

// DecodePDUSessionEstablishmentAccept decodes a NAS message envelope received from
// N3IWF/TNGF (over the NAS TCP connection) expected to contain a DL NAS Transport
// carrying a PDU Session Establishment Accept, and decodes the inner GSM message too.
func DecodePDUSessionEstablishmentAccept(ue *RanUeContext, length int, buffer []byte) (
	*message.PDUSessEstAccept, error,
) {
	if length == 0 {
		return nil, fmt.Errorf("Empty buffer")
	}

	nasEnv, n, err := DecapNasPduFromEnvelope(buffer[:length])
	if err != nil {
		return nil, err
	}

	nasMsg, err := NASDecode(ue, message.SecHdrTypeIntegrityProtectedAndCiphered, nasEnv[:n])
	if err != nil {
		return nil, fmt.Errorf("NAS Decode Fail: %+v", err)
	}

	// The GSM message travels inside the DL NAS transport payload container and
	// has to be parsed separately.
	dlTransport, ok := nasMsg.(*message.DLNASTransport)
	if !ok {
		return nil, fmt.Errorf("expected DLNASTransport, got %T", nasMsg)
	}
	if dlTransport.PayloadCntr == nil {
		return nil, fmt.Errorf("DLNASTransport has no payload container")
	}

	gsmMsg, err := message.ParseGSM(dlTransport.PayloadCntr.Contents)
	if err != nil {
		return nil, fmt.Errorf("NAS Decode Fail: %+v", err)
	}
	accept, ok := gsmMsg.(*message.PDUSessEstAccept)
	if !ok {
		return nil, fmt.Errorf("expected PDUSessEstAccept, got %T", gsmMsg)
	}

	return accept, nil
}

// GetPDUAddress extracts the allocated UE IPv4 address from a PDU Session
// Establishment Accept's PDU Address IE.
func GetPDUAddress(accept *message.PDUSessEstAccept) (net.IP, error) {
	if accept == nil {
		return nil, fmt.Errorf("PDUSessEstAccept is nil")
	} else if addr := accept.PDUAddr; addr != nil {
		if accept.SelectedPDUSessType != nil &&
			accept.SelectedPDUSessType.Value == ie.PDUSessType_IPv4 {
			return net.IP(addr.IPv4), nil
		}
	}

	return nil, fmt.Errorf("PDUAddress is nil")
}

// GetNasPdu extracts and decodes the NAS PDU carried by a DownlinkNASTransport.
// The new ngap API exposes the IE as a field, so there is no need to walk the
// ProtocolIEs list looking for ProtocolIEIDNASPDU any more.
func GetNasPdu(ue *RanUeContext, msg *ngapMessage.DownlinkNASTransport) message.Message {
	if msg == nil || msg.NASPDU == nil {
		return nil
	}

	pkg := []byte(msg.NASPDU.Value)
	m, err := NASDecode(ue, message.GetSecHdrType(pkg), pkg)
	if err != nil {
		return nil
	}
	return m
}

// MobileIdentity5GS decodes the value portion used by the legacy test vectors
// into the typed IE used by the current NAS API.
func MobileIdentity5GS(value []byte) *ie.MobileId5GS {
	mobileIdentity := new(ie.MobileId5GS)
	if err := mobileIdentity.UnmarshalBinary(value); err != nil {
		fmt.Printf("decode 5GS mobile identity: %+v\n", err)
	}
	return mobileIdentity
}

// marshalNasMsg serializes a NAS message, preserving the previous behaviour
// of printing the error and returning whatever was produced.
func marshalNasMsg(m interface{ MarshalBinary() ([]byte, error) }) []byte {
	b, err := m.MarshalBinary()
	if err != nil {
		fmt.Println(err.Error())
	}
	return b
}

// newULNASTransport builds the common ULNASTransport envelope carrying an N1 SM
// payload. Every GetUlNasTransport_* helper differs only in which optional IEs
// it sets, so they all funnel through here.
func newULNASTransport(pduSessionId uint8, payload []byte) *message.ULNASTransport {
	return &message.ULNASTransport{
		PayloadCntrType: &ie.PayloadCntrType{Value: ie.PayloadCntrType_N1SMInfo},
		PayloadCntr:     &ie.PayloadCntr{Contents: payload},
		PDUSessID:       &ie.PDUSessId2{Value: pduSessionId},
	}
}

// setULNASTransportRouting fills the IEs the AMF needs to route an N1 SM
// payload to the right SMF: request type, DNN and S-NSSAI.
func setULNASTransportRouting(m *message.ULNASTransport, requestType ie.ConstReqType, dnnString string, sNssai *models.Snssai) {
	m.ReqType = &ie.ReqType{Value: requestType}
	if dnnString != "" {
		m.DNN = &ie.DNN{Value: dnnString}
	}
	if sNssai != nil {
		// SD is a hex string in the new API; no manual decoding needed.
		m.SNSSAI = &ie.SNSSAI{
			SST: uint8(sNssai.Sst),
			SD:  sNssai.Sd,
		}
	}
}

func GetRegistrationRequest(
	registrationType uint8,
	mobileIdentity *ie.MobileId5GS,
	requestedNSSAI *ie.NSSAI,
	ueSecurityCapability *ie.UESecCapability,
	capability5GMM *ie.Capability5GMM,
	nasMessageContainer []uint8,
	uplinkDataStatus *ie.UplinkDataStatus,
) []byte {
	m := &message.RegReq{
		RegType5GS: &ie.RegType5GS{
			FOR_Pending: true,
			Value:       registrationType,
		},
		Ngksi: &ie.NASKeySetId{
			Tsc: ie.SecCtxTypeNative,
			Ksi: 0x7,
		},
		MobileId5GS:      mobileIdentity,
		UESecCapability:  ueSecurityCapability,
		Capability5GMM:   capability5GMM,
		ReqNSSAI:         requestedNSSAI,
		UplinkDataStatus: uplinkDataStatus,
	}

	if nasMessageContainer != nil {
		m.NASMsgCntr = &ie.NASMsgCntr{Contents: nasMessageContainer}
	}

	return marshalNasMsg(m)
}

func GetPduSessionEstablishmentRequest(pduSessionId uint8) []byte {
	m := &message.PDUSessEstReq{
		PDUSessId: pduSessionId,
		PTI:       0x00,
		IntegrityProtectionMaxDataRate: &ie.IntegrityProtectionMaxDataRate{
			Uplink:   0xff,
			Downlink: 0xff,
		},
		PDUSessType: &ie.PDUSessType{Value: ie.PDUSessType_IPv4},
		SSCMode:     &ie.SSCMode{Mode: ie.SSCMODE1},
		// NOTE: the old packet also requested IP address allocation via NAS
		// signalling. The new ie.ExtCfgOptFromMs has no field for that
		// container and marshalFromMs never emits it, so it is dropped here.
		// free5gc's SMF only reads the DNS / P-CSCF / MTU requests, so the E2E
		// behaviour is unaffected; see the migration report for details.
		ExtendedProtCfgOpts: &ie.ExtendedProtCfgOpts{
			FromMs: &ie.ExtCfgOptFromMs{
				DNSV4Req: true,
				DNSV6Req: true,
			},
		},
	}

	return marshalNasMsg(m)
}

func GetUlNasTransport_PduSessionEstablishmentRequest(pduSessionId uint8, requestType ie.ConstReqType, dnnString string,
	sNssai *models.Snssai,
) []byte {
	m := newULNASTransport(pduSessionId, GetPduSessionEstablishmentRequest(pduSessionId))
	setULNASTransportRouting(m, requestType, dnnString, sNssai)
	return marshalNasMsg(m)
}

func GetUlNasTransport_PduSessionModificationRequest(pduSessionId uint8, requestType ie.ConstReqType, dnnString string,
	sNssai *models.Snssai,
) []byte {
	m := newULNASTransport(pduSessionId, GetPduSessionModificationRequest(pduSessionId))
	setULNASTransportRouting(m, requestType, dnnString, sNssai)
	return marshalNasMsg(m)
}

func GetPduSessionModificationRequest(pduSessionId uint8) []byte {
	return marshalNasMsg(&message.PDUSessModReq{
		PDUSessId: pduSessionId,
		PTI:       0x00,
	})
}

func GetPduSessionModificationComplete(pduSessionId uint8) []byte {
	return marshalNasMsg(&message.PDUSessModComplete{
		PDUSessId: pduSessionId,
		PTI:       0x00,
	})
}

func GetPduSessionModificationCommandReject(pduSessionId uint8) []byte {
	return marshalNasMsg(&message.PDUSessModCmdRej{
		PDUSessId: pduSessionId,
		PTI:       0x00,
		// Cause5GSM is a mandatory V field in this message.
		Cause5GSM: &ie.Cause5GSM{},
	})
}

func GetPduSessionReleaseRequest(pduSessionId uint8) []byte {
	return marshalNasMsg(&message.PDUSessRelReq{
		PDUSessId: pduSessionId,
		PTI:       0x00,
	})
}

func GetPduSessionReleaseComplete(pduSessionId uint8) []byte {
	return marshalNasMsg(&message.PDUSessRelComplete{
		PDUSessId: pduSessionId,
		PTI:       0x00,
	})
}

func GetPduSessionReleaseReject(pduSessionId uint8) []byte {
	return marshalNasMsg(&message.PDUSessRelRej{
		PDUSessId: pduSessionId,
		PTI:       0x00,
		// Cause5GSM is a mandatory V field in this message.
		Cause5GSM: &ie.Cause5GSM{},
	})
}

func GetPduSessionAuthenticationComplete(pduSessionId uint8) []byte {
	return marshalNasMsg(&message.PDUSessAuthComplete{
		PDUSessId: pduSessionId,
		PTI:       0x00,
		EAPMsg:    &ie.EAPMsg{Eap: []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}},
	})
}

func GetUlNasTransport_PduSessionCommonData(pduSessionId uint8, types string) []byte {
	var payload []byte
	switch types {
	case PDUSesModiReq:
		payload = GetPduSessionModificationRequest(pduSessionId)
	case PDUSesModiCmp:
		payload = GetPduSessionModificationComplete(pduSessionId)
	case PDUSesModiCmdRej:
		payload = GetPduSessionModificationCommandReject(pduSessionId)
	case PDUSesRelReq:
		payload = GetPduSessionReleaseRequest(pduSessionId)
	case PDUSesRelCmp:
		payload = GetPduSessionReleaseComplete(pduSessionId)
	case PDUSesRelRej:
		payload = GetPduSessionReleaseReject(pduSessionId)
	case PDUSesAuthCmp:
		payload = GetPduSessionAuthenticationComplete(pduSessionId)
	}

	return marshalNasMsg(newULNASTransport(pduSessionId, payload))
}

func GetIdentityResponse(mobileIdentity *ie.MobileId5GS) []byte {
	return marshalNasMsg(&message.IdRsp{MobileId: mobileIdentity})
}

func GetNotificationResponse(pDUSessionStatus []uint8) []byte {
	m := &message.NotifRsp{PDUSessStatus: &ie.PDUSessStatus{}}
	setPsiFromBuffer(&m.PDUSessStatus.Psi, pDUSessionStatus)
	return marshalNasMsg(m)
}

// setPsiFromBuffer converts the raw PDU session status bitmap the old API
// exposed as a byte buffer into the new ie.Psi bool array. Bit i of octet n
// maps to PSI[n*8+i], matching TS 24.501 9.11.3.44.
func setPsiFromBuffer(psi *ie.Psi, buf []uint8) {
	for octet, b := range buf {
		for bit := 0; bit < 8; bit++ {
			idx := octet*8 + bit
			if idx >= len(psi.PSI) {
				return
			}
			psi.PSI[idx] = b&(1<<uint(bit)) != 0
		}
	}
}

func GetConfigurationUpdateComplete() []byte {
	return marshalNasMsg(&message.CfgUpdateComplete{})
}

func GetServiceRequest(serviceType ie.ConstSvcType) []byte {
	m := &message.SvcReq{
		Ngksi: &ie.NASKeySetId{
			Tsc: ie.SecCtxTypeNative,
			Ksi: 0x01,
		},
		SvcType: &ie.SvcType{Value: serviceType},
		TMSI5GS: &ie.MobileId5GS{
			TypeOfId: ie.IdType_5GS_TMSI,
			AMFSetID: uint16(0xFE) << 2,
			TMSI5G:   [4]byte{0, 0, 0, 1},
		},
	}

	switch serviceType {
	case ie.SvcType_MobileTermSvc:
		m.AllowedPDUSessStatus = &ie.AllowedPDUSessStatus{}
		setPsiFromBuffer(&m.AllowedPDUSessStatus.Psi, []uint8{0x00, 0x08})
	case ie.SvcType_Data:
		m.UplinkDataStatus = &ie.UplinkDataStatus{}
		setPsiFromBuffer(&m.UplinkDataStatus.Psi, []uint8{0x00, 0x04})
	case ie.SvcType_Signalling:
	}

	return marshalNasMsg(m)
}

func GetAuthenticationResponse(authenticationResponseParam []uint8, eapMsg string) []byte {
	m := &message.AuthRsp{}

	if len(authenticationResponseParam) > 0 {
		m.AuthRspParam = &ie.AuthRspParam{Res: authenticationResponseParam[0:16]}
	} else if eapMsg != "" {
		rawEapMsg, err := base64.StdEncoding.DecodeString(eapMsg)
		if err != nil {
			fmt.Printf("EAP decode error: %+v\n", err)
		}
		m.EAPMsg = &ie.EAPMsg{Eap: rawEapMsg}
	}

	return marshalNasMsg(m)
}

func GetAuthenticationFailure(cause5GMM uint8, authenticationFailureParam []uint8) []byte {
	m := &message.AuthFailure{
		Cause5GMM: &ie.Cause5GMM{Value: cause5GMM},
	}

	if cause5GMM == ie.Cause5GMM_SynchFailure {
		m.AuthFailureParam = &ie.AuthFailureParam{Value: authenticationFailureParam}
	}

	return marshalNasMsg(m)
}

func GetRegistrationComplete(sorTransparentContainer []uint8) []byte {
	m := &message.RegComplete{}

	if sorTransparentContainer != nil {
		m.SORTransparentCntr = &ie.SORTransparentCntr{}
	}

	return marshalNasMsg(m)
}

// TS 24.501 8.2.26.
func GetSecurityModeComplete(nasMessageContainer []uint8) []byte {
	m := &message.SecModeComplete{
		// Same three digits the old packet set (digit 1, P-1 and P); the rest
		// stay zero. The new library additionally pads the trailing unused BCD
		// nibble with 0xF as TS 23.003 requires, which the old one left at 0.
		IMEISV: &ie.MobileId5GS{
			TypeOfId:     ie.IdType_5GS_IMEISV,
			OddEvenIndic: 0,
			IMEISV:       [16]uint8{1, 1, 1},
		},
	}

	if nasMessageContainer != nil {
		m.NASMsgCntr = &ie.NASMsgCntr{Contents: nasMessageContainer}
	}

	return marshalNasMsg(m)
}

func GetSecurityModeReject(cause5GMM uint8) []byte {
	return marshalNasMsg(&message.SecModeRej{
		Cause5GMM: &ie.Cause5GMM{Value: cause5GMM},
	})
}

func GetDeregistrationRequest(accessType uint8, switchOff uint8, ngKsi uint8,
	mobileIdentity5GS *ie.MobileId5GS,
) []byte {
	return marshalNasMsg(&message.DeregReqUEOrig{
		DeregType: &ie.DeregType{
			AccessType:    accessType,
			Switchoff:     switchOff != 0,
			ReregRequired: false,
		},
		Ngksi: &ie.NASKeySetId{
			Tsc: ie.SecCtxType(ngKsi),
			Ksi: ngKsi,
		},
		MobileId5GS: mobileIdentity5GS,
	})
}

func GetDeregistrationAccept() []byte {
	return marshalNasMsg(&message.DeregAcceptUETerm{})
}

func GetStatus5GMM(cause uint8) []byte {
	return marshalNasMsg(&message.Status5GMM{
		Cause5GMM: &ie.Cause5GMM{Value: cause},
	})
}

func GetStatus5GSM(pduSessionId uint8, cause uint8) []byte {
	return marshalNasMsg(&message.Status5GSM{
		PDUSessId: pduSessionId,
		PTI:       0x00,
		Cause5GSM: &ie.Cause5GSM{Value: cause},
	})
}

func GetUlNasTransport_Status5GSM(pduSessionId uint8, cause uint8) []byte {
	return marshalNasMsg(newULNASTransport(pduSessionId, GetStatus5GSM(pduSessionId, cause)))
}

func GetUlNasTransport_PduSessionReleaseRequest(pduSessionId uint8) []byte {
	return marshalNasMsg(newULNASTransport(pduSessionId, GetPduSessionReleaseRequest(pduSessionId)))
}

func GetUlNasTransport_PduSessionReleaseComplete(pduSessionId uint8, requestType ie.ConstReqType, dnnString string,
	sNssai *models.Snssai,
) []byte {
	m := newULNASTransport(pduSessionId, GetPduSessionReleaseComplete(pduSessionId))
	setULNASTransportRouting(m, requestType, dnnString, sNssai)
	return marshalNasMsg(m)
}
