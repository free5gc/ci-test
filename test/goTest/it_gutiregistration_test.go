package test

import (
	"fmt"
	"strconv"
	"testing"
	"time"

	nasIE "github.com/free5gc/nas/ie"
	nasMessage "github.com/free5gc/nas/message"
	ngapMessage "github.com/free5gc/ngap/message"
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
	_, err = ngapMessage.Parse(recvMsg[:n])
	require.Nil(t, err)

	// New UE
	ue := NewRanUeContext(UE_IMSI, 1, nasMessage.AlgCiphering128NEA0, nasMessage.AlgIntegrity128NIA2, models.AccessType_3_GPP_ACCESS)
	ue.AmfUeNgapId = 1
	ue.AuthenticationSubs = GetAuthSubscription(UE_K, UE_OPC, "")

	// send InitialUeMessage(Registration Request)
	SUCI5GS := MobileIdentity5GS(
		[]uint8{0x01, 0x02, 0xf8, 0x39, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10})
	ueSecurityCapability := ue.GetUESecurityCapability()
	registrationRequest := GetRegistrationRequest(
		nasIE.RegType_InitialReg, SUCI5GS, nil, ueSecurityCapability, nil, nil, nil)
	sendMsg, err = GetInitialUEMessage(ue.RanUeNgapId, registrationRequest, "")
	require.Nil(t, err)
	_, err = n2Conn.Write(sendMsg)
	require.Nil(t, err)

	// receive NAS Authentication Request
	n, err = n2Conn.Read(recvMsg)
	require.Nil(t, err)
	ngapMsg, err := ngapMessage.Parse(recvMsg[:n])
	require.Nil(t, err)

	// Calculate for RES*
	nasPdu := GetNasPdu(ue, ngapMsg.(*ngapMessage.DownlinkNASTransport))
	require.NotNil(t, nasPdu)
	require.Equal(t, nasPdu.MsgType(), nasMessage.MsgTypeAuthReq,
		"Received wrong GMM message. Expected Authentication Request.")
	rand := nasPdu.(*nasMessage.AuthReq).AuthParamRAND5GAuthChlg.Rand
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
	ngapPdu, err := ngapMessage.Parse(recvMsg[:n])
	require.Nil(t, err)
	require.NotNil(t, ngapPdu)
	nasPdu = GetNasPdu(ue, ngapPdu.(*ngapMessage.DownlinkNASTransport))
	require.NotNil(t, nasPdu)
	require.Equal(t, nasPdu.MsgType(), nasMessage.MsgTypeSecModeCmd,
		"Received wrong GMM message. Expected Security Mode Command.")

	// send NAS Security Mode Complete
	registrationRequestWith5GMM := GetRegistrationRequest(nasIE.RegType_InitialReg,
		SUCI5GS, nil, ueSecurityCapability, ue.Get5GMMCapability(), nil, nil)
	pdu = GetSecurityModeComplete(registrationRequestWith5GMM)
	pdu, err = EncodeNasPduWithSecurity(ue, pdu, nasMessage.SecHdrTypeIntegrityProtectedAndCipheredWithNew5gNasSecCtx, true, true)
	require.Nil(t, err)
	sendMsg, err = GetUplinkNASTransport(ue.AmfUeNgapId, ue.RanUeNgapId, pdu)
	require.Nil(t, err)
	_, err = n2Conn.Write(sendMsg)
	require.Nil(t, err)

	// receive ngap Initial Context Setup Request
	n, err = n2Conn.Read(recvMsg)
	require.Nil(t, err)
	_, err = ngapMessage.Parse(recvMsg[:n])
	require.Nil(t, err)

	// send ngap Initial Context Setup Response
	sendMsg, err = GetInitialContextSetupResponse(ue.AmfUeNgapId, ue.RanUeNgapId)
	require.Nil(t, err)
	_, err = n2Conn.Write(sendMsg)
	require.Nil(t, err)

	// send NAS Registration Complete
	pdu = GetRegistrationComplete(nil)
	pdu, err = EncodeNasPduWithSecurity(ue, pdu, nasMessage.SecHdrTypeIntegrityProtectedAndCiphered, true, false)
	require.Nil(t, err)
	sendMsg, err = GetUplinkNASTransport(ue.AmfUeNgapId, ue.RanUeNgapId, pdu)
	require.Nil(t, err)
	_, err = n2Conn.Write(sendMsg)
	require.Nil(t, err)

	// receive UE Configuration Update Command (equivalent to recvUeConfigUpdateCmd in reference test)
	n, err = n2Conn.Read(recvMsg)
	assert.Nil(t, err)
	ngapPdu, err = ngapMessage.Parse(recvMsg[:n])
	assert.Nil(t, err)
	assert.Equal(t, ngapPdu.MessageType(), ngapMessage.MessageTypeInitiatingMessage, "Not MessageTypeInitiatingMessage")
	assert.Equal(t, ngapPdu.ProcedureCode(), ngapMessage.ProcedureCodeDownlinkNASTransport, "Not ProcedureCodeDownlinkNASTransport")

	time.Sleep(500 * time.Millisecond)

	// send NAS Deregistration Request (UE Originating)
	// 5G-GUTI is assigned by AMF during registration; verify buffer matches AMF assignment if test fails
	GUTI5GS := MobileIdentity5GS(
		[]uint8{0xf2, 0x02, 0xf8, 0x39, 0xca, 0xfe, 0x00, 0x00, 0x00, 0x00, 0x01})
	pdu = GetDeregistrationRequest(nasIE.AccessType_3gpp, 0, 0x04, GUTI5GS)
	pdu, err = EncodeNasPduWithSecurity(ue, pdu, nasMessage.SecHdrTypeIntegrityProtectedAndCiphered, true, false)
	require.Nil(t, err)
	sendMsg, err = GetUplinkNASTransport(ue.AmfUeNgapId, ue.RanUeNgapId, pdu)
	require.Nil(t, err)
	_, err = n2Conn.Write(sendMsg)
	require.Nil(t, err)

	time.Sleep(500 * time.Millisecond)

	// receive NAS Deregistration Accept
	n, err = n2Conn.Read(recvMsg)
	require.Nil(t, err)
	ngapMsg, err = ngapMessage.Parse(recvMsg[:n])
	require.Nil(t, err)
	require.Equal(t, ngapMessage.MessageTypeInitiatingMessage, ngapMsg.MessageType())
	require.Equal(t, ngapMessage.ProcedureCodeDownlinkNASTransport, ngapMsg.ProcedureCode())
	nasPdu = GetNasPdu(ue, ngapMsg.(*ngapMessage.DownlinkNASTransport))
	require.NotNil(t, nasPdu)
	require.Equal(t, nasPdu.MsgType(), nasMessage.MsgTypeDeregAcceptUEOrig,
		"Received wrong GMM message. Expected Deregistration Accept.")

	// receive ngap UE Context Release Command
	n, err = n2Conn.Read(recvMsg)
	require.Nil(t, err)
	_, err = ngapMessage.Parse(recvMsg[:n])
	require.Nil(t, err)

	// send ngap UE Context Release Complete
	sendMsg, err = GetUEContextReleaseComplete(ue.AmfUeNgapId, ue.RanUeNgapId, nil)
	require.Nil(t, err)
	_, err = n2Conn.Write(sendMsg)
	require.Nil(t, err)

	time.Sleep(200 * time.Millisecond)

	// ========================= Second Registration - Register with GUTI =========================

	ue.AmfUeNgapId = 2
	innerRegistrationRequest := GetRegistrationRequest(nasIE.RegType_InitialReg,
		GUTI5GS, nil, ue.GetUESecurityCapability(), ue.Get5GMMCapability(), nil, nil)
	registrationRequest = GetRegistrationRequest(nasIE.RegType_InitialReg,
		GUTI5GS, nil, ueSecurityCapability, nil, innerRegistrationRequest, nil)
	pdu, err = EncodeNasPduWithSecurity(ue, registrationRequest, nasMessage.SecHdrTypeIntegrityProtected, true, true)
	require.Nil(t, err)
	sendMsg, err = GetInitialUEMessage(ue.RanUeNgapId, pdu, "")
	require.Nil(t, err)
	_, err = n2Conn.Write(sendMsg)
	require.Nil(t, err)

	// receive NAS Identity Request
	n, err = n2Conn.Read(recvMsg)
	require.Nil(t, err)
	ngapMsg, err = ngapMessage.Parse(recvMsg[:n])
	require.Nil(t, err)
	require.Equal(t, ngapMessage.MessageTypeInitiatingMessage, ngapMsg.MessageType())
	require.Equal(t, ngapMessage.ProcedureCodeDownlinkNASTransport, ngapMsg.ProcedureCode())
	nasPdu = GetNasPdu(ue, ngapMsg.(*ngapMessage.DownlinkNASTransport))
	require.NotNil(t, nasPdu)
	require.Equal(t, nasPdu.MsgType(), nasMessage.MsgTypeIdReq,
		"Received wrong GMM message. Expected Identity Request.")

	// update AMF UE NGAP ID
	ue.AmfUeNgapId = ngapMsg.(*ngapMessage.DownlinkNASTransport).AMFUENGAPID.Value

	// send NAS Identity Response
	pdu = GetIdentityResponse(SUCI5GS)
	require.Nil(t, err)

	sendMsg, err = GetUplinkNASTransport(ue.AmfUeNgapId, ue.RanUeNgapId, pdu)
	require.Nil(t, err)
	_, err = n2Conn.Write(sendMsg)
	require.Nil(t, err)

	// receive NAS Authentication Request
	n, err = n2Conn.Read(recvMsg)
	require.Nil(t, err)
	ngapMsg, err = ngapMessage.Parse(recvMsg[:n])
	require.Nil(t, err)
	require.Equal(t, ngapMessage.MessageTypeInitiatingMessage, ngapMsg.MessageType())
	require.Equal(t, ngapMessage.ProcedureCodeDownlinkNASTransport, ngapMsg.ProcedureCode())
	nasPdu = GetNasPdu(ue, ngapMsg.(*ngapMessage.DownlinkNASTransport))
	require.NotNil(t, nasPdu)
	require.Equal(t, nasPdu.MsgType(), nasMessage.MsgTypeAuthReq,
		"Received wrong GMM message. Expected Authentication Request.")

	// Calculate for RES* (SQN incremented because network updated SQN after first authentication)
	rand = nasPdu.(*nasMessage.AuthReq).AuthParamRAND5GAuthChlg.Rand
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
	ngapMsg, err = ngapMessage.Parse(recvMsg[:n])
	require.Nil(t, err)
	require.Equal(t, ngapMessage.MessageTypeInitiatingMessage, ngapMsg.MessageType())
	require.Equal(t, ngapMessage.ProcedureCodeDownlinkNASTransport, ngapMsg.ProcedureCode())
	nasPdu = GetNasPdu(ue, ngapMsg.(*ngapMessage.DownlinkNASTransport))
	require.NotNil(t, nasPdu)
	require.Equal(t, nasPdu.MsgType(), nasMessage.MsgTypeSecModeCmd,
		"Received wrong GMM message. Expected Security Mode Command.")

	// send NAS Security Mode Complete
	pdu = GetSecurityModeComplete(innerRegistrationRequest)
	pdu, err = EncodeNasPduWithSecurity(ue, pdu, nasMessage.SecHdrTypeIntegrityProtectedAndCipheredWithNew5gNasSecCtx, true, true)
	require.Nil(t, err)
	sendMsg, err = GetUplinkNASTransport(ue.AmfUeNgapId, ue.RanUeNgapId, pdu)
	require.Nil(t, err)
	_, err = n2Conn.Write(sendMsg)
	require.Nil(t, err)

	// receive ngap Initial Context Setup Request
	n, err = n2Conn.Read(recvMsg)
	require.Nil(t, err)
	_, err = ngapMessage.Parse(recvMsg[:n])
	require.Nil(t, err)

	// send ngap Initial Context Setup Response
	sendMsg, err = GetInitialContextSetupResponse(ue.AmfUeNgapId, ue.RanUeNgapId)
	require.Nil(t, err)
	_, err = n2Conn.Write(sendMsg)
	require.Nil(t, err)

	// send NAS Registration Complete
	pdu = GetRegistrationComplete(nil)
	pdu, err = EncodeNasPduWithSecurity(ue, pdu, nasMessage.SecHdrTypeIntegrityProtectedAndCiphered, true, false)
	assert.Nil(t, err)
	sendMsg, err = GetUplinkNASTransport(ue.AmfUeNgapId, ue.RanUeNgapId, pdu)
	assert.Nil(t, err)
	_, err = n2Conn.Write(sendMsg)
	assert.Nil(t, err)

	// receive UE Configuration Update Command (equivalent to recvUeConfigUpdateCmd in reference test)
	n, err = n2Conn.Read(recvMsg)
	assert.Nil(t, err)
	ngapPdu, err = ngapMessage.Parse(recvMsg[:n])
	assert.Nil(t, err)
	assert.Equal(t, ngapPdu.MessageType(), ngapMessage.MessageTypeInitiatingMessage, "Not MessageTypeInitiatingMessage")
	assert.Equal(t, ngapPdu.ProcedureCode(), ngapMessage.ProcedureCodeDownlinkNASTransport, "Not ProcedureCodeDownlinkNASTransport")

	time.Sleep(1000 * time.Millisecond)
}
