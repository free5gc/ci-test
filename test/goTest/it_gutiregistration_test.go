package test

import (
	"fmt"
	"strconv"
	"testing"
	"time"

	"github.com/free5gc/nas"
	"github.com/free5gc/nas/nasMessage"
	"github.com/free5gc/nas/nasType"
	"github.com/free5gc/nas/security"
	"github.com/free5gc/ngap"
	"github.com/free5gc/ngap/ngapType"
	"github.com/free5gc/openapi/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGUTIRegistration(t *testing.T) {
	var (
		n       int
		sendMsg []byte
		recvMsg = make([]byte, 2048)
		err     error
	)

	// RAN connect to AMF
	n2Conn, err := connectToAmf(AMF_IP, IT_IP, AMF_PORT, IT_N2_PORT)
	require.Nil(t, err)
	defer n2Conn.Close()

	// send NGSetupRequest
	sendMsg, err = GetNGSetupRequest([]byte(IT_GNB_ID), 24, "free5GC")
	require.Nil(t, err)
	_, err = n2Conn.Write(sendMsg)
	require.Nil(t, err)

	// receive NGSetupResponse
	n, err = n2Conn.Read(recvMsg)
	require.Nil(t, err)
	_, err = ngap.Decoder(recvMsg[:n])
	require.Nil(t, err)

	// New UE
	ue := NewRanUeContext(UE_IMSI, 1, security.AlgCiphering128NEA0, security.AlgIntegrity128NIA2, models.AccessType__3_GPP_ACCESS)
	ue.AmfUeNgapId = 1
	ue.AuthenticationSubs = GetAuthSubscription(UE_K, UE_OPC, "")

	// send InitialUeMessage(Registration Request)
	SUCI5GS := nasType.MobileIdentity5GS{
		Len:    13, // suci
		Buffer: []uint8{0x01, 0x02, 0xf8, 0x39, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10},
	}
	ueSecurityCapability := ue.GetUESecurityCapability()
	registrationRequest := GetRegistrationRequest(
		nasMessage.RegistrationType5GSInitialRegistration, SUCI5GS, nil, ueSecurityCapability, nil, nil, nil)
	sendMsg, err = GetInitialUEMessage(ue.RanUeNgapId, registrationRequest, "")
	require.Nil(t, err)
	_, err = n2Conn.Write(sendMsg)
	require.Nil(t, err)

	// receive NAS Authentication Request
	n, err = n2Conn.Read(recvMsg)
	require.Nil(t, err)
	ngapMsg, err := ngap.Decoder(recvMsg[:n])
	require.Nil(t, err)

	// Calculate for RES*
	nasPdu := GetNasPdu(ue, ngapMsg.InitiatingMessage.Value.DownlinkNASTransport)
	require.NotNil(t, nasPdu)
	require.NotNil(t, nasPdu.GmmMessage, "GMM message is nil")
	require.Equal(t, nasPdu.GmmHeader.GetMessageType(), nas.MsgTypeAuthenticationRequest,
		"Received wrong GMM message. Expected Authentication Request.")
	rand := nasPdu.AuthenticationRequest.GetRANDValue()
	resStat := ue.DeriveRESstarAndSetKey(ue.AuthenticationSubs, rand[:], "5G:mnc093.mcc208.3gppnetwork.org")

	// send NAS Authentication Response
	pdu := GetAuthenticationResponse(resStat, "")
	sendMsg, err = GetUplinkNASTransport(ue.AmfUeNgapId, ue.RanUeNgapId, pdu)
	require.Nil(t, err)
	_, err = n2Conn.Write(sendMsg)
	require.Nil(t, err)

	// receive NAS Security Mode Command
	n, err = n2Conn.Read(recvMsg)
	require.Nil(t, err)
	ngapPdu, err := ngap.Decoder(recvMsg[:n])
	require.Nil(t, err)
	require.NotNil(t, ngapPdu)
	nasPdu = GetNasPdu(ue, ngapPdu.InitiatingMessage.Value.DownlinkNASTransport)
	require.NotNil(t, nasPdu)
	require.NotNil(t, nasPdu.GmmMessage, "GMM message is nil")
	require.Equal(t, nasPdu.GmmHeader.GetMessageType(), nas.MsgTypeSecurityModeCommand,
		"Received wrong GMM message. Expected Security Mode Command.")

	// send NAS Security Mode Complete
	registrationRequestWith5GMM := GetRegistrationRequest(nasMessage.RegistrationType5GSInitialRegistration,
		SUCI5GS, nil, ueSecurityCapability, ue.Get5GMMCapability(), nil, nil)
	pdu = GetSecurityModeComplete(registrationRequestWith5GMM)
	pdu, err = EncodeNasPduWithSecurity(ue, pdu, nas.SecurityHeaderTypeIntegrityProtectedAndCipheredWithNew5gNasSecurityContext, true, true)
	require.Nil(t, err)
	sendMsg, err = GetUplinkNASTransport(ue.AmfUeNgapId, ue.RanUeNgapId, pdu)
	require.Nil(t, err)
	_, err = n2Conn.Write(sendMsg)
	require.Nil(t, err)

	// receive ngap Initial Context Setup Request
	n, err = n2Conn.Read(recvMsg)
	require.Nil(t, err)
	_, err = ngap.Decoder(recvMsg[:n])
	require.Nil(t, err)

	// send ngap Initial Context Setup Response
	sendMsg, err = GetInitialContextSetupResponse(ue.AmfUeNgapId, ue.RanUeNgapId)
	require.Nil(t, err)
	_, err = n2Conn.Write(sendMsg)
	require.Nil(t, err)

	// send NAS Registration Complete
	pdu = GetRegistrationComplete(nil)
	pdu, err = EncodeNasPduWithSecurity(ue, pdu, nas.SecurityHeaderTypeIntegrityProtectedAndCiphered, true, false)
	require.Nil(t, err)
	sendMsg, err = GetUplinkNASTransport(ue.AmfUeNgapId, ue.RanUeNgapId, pdu)
	require.Nil(t, err)
	_, err = n2Conn.Write(sendMsg)
	require.Nil(t, err)

	// receive UE Configuration Update Command (equivalent to recvUeConfigUpdateCmd in reference test)
	n, err = n2Conn.Read(recvMsg)
	assert.Nil(t, err)
	ngapPdu, err = ngap.Decoder(recvMsg[:n])
	assert.Nil(t, err)
	assert.Equal(t, ngapPdu.Present, ngapType.NGAPPDUPresentInitiatingMessage, "Not NGAPPDUPresentInitiatingMessage")
	assert.Equal(t, ngapPdu.InitiatingMessage.ProcedureCode.Value, ngapType.ProcedureCodeDownlinkNASTransport, "Not ProcedureCodeDownlinkNASTransport")

	time.Sleep(500 * time.Millisecond)

	// send NAS Deregistration Request (UE Originating)
	// 5G-GUTI is assigned by AMF during registration; verify buffer matches AMF assignment if test fails
	GUTI5GS := nasType.MobileIdentity5GS{
		Len:    11, // 5g-guti
		Buffer: []uint8{0xf2, 0x02, 0xf8, 0x39, 0xca, 0xfe, 0x00, 0x00, 0x00, 0x00, 0x01},
	}
	pdu = GetDeregistrationRequest(nasMessage.AccessType3GPP, 0, 0x04, GUTI5GS)
	pdu, err = EncodeNasPduWithSecurity(ue, pdu, nas.SecurityHeaderTypeIntegrityProtectedAndCiphered, true, false)
	require.Nil(t, err)
	sendMsg, err = GetUplinkNASTransport(ue.AmfUeNgapId, ue.RanUeNgapId, pdu)
	require.Nil(t, err)
	_, err = n2Conn.Write(sendMsg)
	require.Nil(t, err)

	time.Sleep(500 * time.Millisecond)

	// receive NAS Deregistration Accept
	n, err = n2Conn.Read(recvMsg)
	require.Nil(t, err)
	ngapMsg, err = ngap.Decoder(recvMsg[:n])
	require.Nil(t, err)
	require.Equal(t, ngapType.NGAPPDUPresentInitiatingMessage, ngapMsg.Present)
	require.Equal(t, ngapType.ProcedureCodeDownlinkNASTransport, ngapMsg.InitiatingMessage.ProcedureCode.Value)
	require.Equal(t, ngapType.InitiatingMessagePresentDownlinkNASTransport, ngapMsg.InitiatingMessage.Value.Present)
	nasPdu = GetNasPdu(ue, ngapMsg.InitiatingMessage.Value.DownlinkNASTransport)
	require.NotNil(t, nasPdu)
	require.NotNil(t, nasPdu.GmmMessage, "GMM message is nil")
	require.Equal(t, nasPdu.GmmHeader.GetMessageType(), nas.MsgTypeDeregistrationAcceptUEOriginatingDeregistration,
		"Received wrong GMM message. Expected Deregistration Accept.")

	// receive ngap UE Context Release Command
	n, err = n2Conn.Read(recvMsg)
	require.Nil(t, err)
	_, err = ngap.Decoder(recvMsg[:n])
	require.Nil(t, err)

	// send ngap UE Context Release Complete
	sendMsg, err = GetUEContextReleaseComplete(ue.AmfUeNgapId, ue.RanUeNgapId, nil)
	require.Nil(t, err)
	_, err = n2Conn.Write(sendMsg)
	require.Nil(t, err)

	time.Sleep(200 * time.Millisecond)

	// ========================= Second Registration - Register with GUTI =========================

	ue.AmfUeNgapId = 2
	innerRegistrationRequest := GetRegistrationRequest(nasMessage.RegistrationType5GSInitialRegistration,
		GUTI5GS, nil, ue.GetUESecurityCapability(), ue.Get5GMMCapability(), nil, nil)
	registrationRequest = GetRegistrationRequest(nasMessage.RegistrationType5GSInitialRegistration,
		GUTI5GS, nil, ueSecurityCapability, nil, innerRegistrationRequest, nil)
	pdu, err = EncodeNasPduWithSecurity(ue, registrationRequest, nas.SecurityHeaderTypeIntegrityProtected, true, true)
	require.Nil(t, err)
	sendMsg, err = GetInitialUEMessage(ue.RanUeNgapId, pdu, "")
	require.Nil(t, err)
	_, err = n2Conn.Write(sendMsg)
	require.Nil(t, err)

	// receive NAS Identity Request
	n, err = n2Conn.Read(recvMsg)
	require.Nil(t, err)
	ngapMsg, err = ngap.Decoder(recvMsg[:n])
	require.Nil(t, err)
	require.Equal(t, ngapType.NGAPPDUPresentInitiatingMessage, ngapMsg.Present)
	require.Equal(t, ngapType.ProcedureCodeDownlinkNASTransport, ngapMsg.InitiatingMessage.ProcedureCode.Value)
	require.Equal(t, ngapType.InitiatingMessagePresentDownlinkNASTransport, ngapMsg.InitiatingMessage.Value.Present)
	nasPdu = GetNasPdu(ue, ngapMsg.InitiatingMessage.Value.DownlinkNASTransport)
	require.NotNil(t, nasPdu)
	require.NotNil(t, nasPdu.GmmMessage, "GMM message is nil")
	require.Equal(t, nasPdu.GmmHeader.GetMessageType(), nas.MsgTypeIdentityRequest,
		"Received wrong GMM message. Expected Identity Request.")

	// update AMF UE NGAP ID
	ue.AmfUeNgapId = ngapMsg.InitiatingMessage.
		Value.DownlinkNASTransport.
		ProtocolIEs.List[0].Value.AMFUENGAPID.Value

	// send NAS Identity Response
	mobileIdentity := nasType.MobileIdentity{
		Len:    SUCI5GS.Len,
		Buffer: SUCI5GS.Buffer,
	}
	pdu = GetIdentityResponse(mobileIdentity)
	require.Nil(t, err)

	sendMsg, err = GetUplinkNASTransport(ue.AmfUeNgapId, ue.RanUeNgapId, pdu)
	require.Nil(t, err)
	_, err = n2Conn.Write(sendMsg)
	require.Nil(t, err)

	// receive NAS Authentication Request
	n, err = n2Conn.Read(recvMsg)
	require.Nil(t, err)
	ngapMsg, err = ngap.Decoder(recvMsg[:n])
	require.Nil(t, err)
	require.Equal(t, ngapType.NGAPPDUPresentInitiatingMessage, ngapMsg.Present)
	require.Equal(t, ngapType.ProcedureCodeDownlinkNASTransport, ngapMsg.InitiatingMessage.ProcedureCode.Value)
	require.Equal(t, ngapType.InitiatingMessagePresentDownlinkNASTransport, ngapMsg.InitiatingMessage.Value.Present)
	nasPdu = GetNasPdu(ue, ngapMsg.InitiatingMessage.Value.DownlinkNASTransport)
	require.NotNil(t, nasPdu)
	require.NotNil(t, nasPdu.GmmMessage, "GMM message is nil")
	require.Equal(t, nasPdu.GmmHeader.GetMessageType(), nas.MsgTypeAuthenticationRequest,
		"Received wrong GMM message. Expected Authentication Request.")

	// Calculate for RES* (SQN incremented because network updated SQN after first authentication)
	rand = nasPdu.AuthenticationRequest.GetRANDValue()
	sqn, _ := strconv.ParseUint(ue.AuthenticationSubs.SequenceNumber.Sqn, 16, 48)
	sqn++
	ue.AuthenticationSubs.SequenceNumber.Sqn = fmt.Sprintf("%012x", sqn)
	resStat = ue.DeriveRESstarAndSetKey(ue.AuthenticationSubs, rand[:], "5G:mnc093.mcc208.3gppnetwork.org")

	// send NAS Authentication Response
	pdu = GetAuthenticationResponse(resStat, "")
	sendMsg, err = GetUplinkNASTransport(ue.AmfUeNgapId, ue.RanUeNgapId, pdu)
	require.Nil(t, err)
	_, err = n2Conn.Write(sendMsg)
	require.Nil(t, err)

	// receive NAS Security Mode Command
	n, err = n2Conn.Read(recvMsg)
	require.Nil(t, err)
	ngapMsg, err = ngap.Decoder(recvMsg[:n])
	require.Nil(t, err)
	require.Equal(t, ngapType.NGAPPDUPresentInitiatingMessage, ngapMsg.Present)
	require.Equal(t, ngapType.ProcedureCodeDownlinkNASTransport, ngapMsg.InitiatingMessage.ProcedureCode.Value)
	require.Equal(t, ngapType.InitiatingMessagePresentDownlinkNASTransport, ngapMsg.InitiatingMessage.Value.Present)
	nasPdu = GetNasPdu(ue, ngapMsg.InitiatingMessage.Value.DownlinkNASTransport)
	require.NotNil(t, nasPdu)
	require.NotNil(t, nasPdu.GmmMessage, "GMM message is nil")
	require.Equal(t, nasPdu.GmmHeader.GetMessageType(), nas.MsgTypeSecurityModeCommand,
		"Received wrong GMM message. Expected Security Mode Command.")

	// send NAS Security Mode Complete
	pdu = GetSecurityModeComplete(innerRegistrationRequest)
	pdu, err = EncodeNasPduWithSecurity(ue, pdu, nas.SecurityHeaderTypeIntegrityProtectedAndCipheredWithNew5gNasSecurityContext, true, true)
	require.Nil(t, err)
	sendMsg, err = GetUplinkNASTransport(ue.AmfUeNgapId, ue.RanUeNgapId, pdu)
	require.Nil(t, err)
	_, err = n2Conn.Write(sendMsg)
	require.Nil(t, err)

	// receive ngap Initial Context Setup Request
	n, err = n2Conn.Read(recvMsg)
	require.Nil(t, err)
	_, err = ngap.Decoder(recvMsg[:n])
	require.Nil(t, err)

	// send ngap Initial Context Setup Response
	sendMsg, err = GetInitialContextSetupResponse(ue.AmfUeNgapId, ue.RanUeNgapId)
	require.Nil(t, err)
	_, err = n2Conn.Write(sendMsg)
	require.Nil(t, err)

	// send NAS Registration Complete
	pdu = GetRegistrationComplete(nil)
	pdu, err = EncodeNasPduWithSecurity(ue, pdu, nas.SecurityHeaderTypeIntegrityProtectedAndCiphered, true, false)
	assert.Nil(t, err)
	sendMsg, err = GetUplinkNASTransport(ue.AmfUeNgapId, ue.RanUeNgapId, pdu)
	assert.Nil(t, err)
	_, err = n2Conn.Write(sendMsg)
	assert.Nil(t, err)

	// receive UE Configuration Update Command (equivalent to recvUeConfigUpdateCmd in reference test)
	n, err = n2Conn.Read(recvMsg)
	assert.Nil(t, err)
	ngapPdu, err = ngap.Decoder(recvMsg[:n])
	assert.Nil(t, err)
	assert.Equal(t, ngapPdu.Present, ngapType.NGAPPDUPresentInitiatingMessage, "Not NGAPPDUPresentInitiatingMessage")
	assert.Equal(t, ngapPdu.InitiatingMessage.ProcedureCode.Value, ngapType.ProcedureCodeDownlinkNASTransport, "Not ProcedureCodeDownlinkNASTransport")

	time.Sleep(1000 * time.Millisecond)
}
