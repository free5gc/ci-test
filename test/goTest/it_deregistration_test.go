package test

import (
	"testing"
	"time"

	nasIE "github.com/free5gc/nas/ie"
	nasMessage "github.com/free5gc/nas/message"
	ngapMessage "github.com/free5gc/ngap/message"
	"github.com/free5gc/openapi/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDeregistration(t *testing.T) {
	var (
		n       int
		sendMsg []byte
		recvMsg = make([]byte, 2048)
		err     error
	)

	// RAN connect to AMF
	n2Conn, err := connectToAmf(AMF_IP, IT_IP, AMF_PORT, IT_N2_PORT)
	assert.Nil(t, err, "connect to AMF failed: %+v", err)
	defer n2Conn.Close()

	// send NGSetupRequest
	sendMsg, err = GetNGSetupRequest([]byte(IT_GNB_ID), 24, "free5GC")
	assert.Nil(t, err)
	_, err = n2Conn.Write(sendMsg)
	assert.Nil(t, err)

	// receive NGSetupResponse
	n, err = n2Conn.Read(recvMsg)
	assert.Nil(t, err)
	_, err = ngapMessage.Parse(recvMsg[:n])
	assert.Nil(t, err)

	// New UE
	ue := NewRanUeContext(UE_IMSI, 1, nasMessage.AlgCiphering128NEA0, nasMessage.AlgIntegrity128NIA2, models.AccessType_3_GPP_ACCESS)
	ue.AmfUeNgapId = 1
	ue.AuthenticationSubs = GetAuthSubscription(UE_K, UE_OPC, "")

	// send InitialUeMessage(Registration Request)
	mobileIdentity5GS := MobileIdentity5GS(
		[]uint8{0x01, 0x02, 0xf8, 0x39, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10})
	ueSecurityCapability := ue.GetUESecurityCapability()
	registrationRequest := GetRegistrationRequest(
		nasIE.RegType_InitialReg, mobileIdentity5GS, nil, ueSecurityCapability, nil, nil, nil)
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
	require.Equal(t, nasPdu.MsgType(), nasMessage.MsgTypeAuthReq, "Received wrong GMM message. Expected Authentication Request.")
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
	require.Equal(t, nasPdu.MsgType(), nasMessage.MsgTypeSecModeCmd, "Received wrong GMM message. Expected Security Mode Command.")

	// send NAS Security Mode Complete
	registrationRequestWith5GMM := GetRegistrationRequest(
		nasIE.RegType_InitialReg, mobileIdentity5GS, nil, ueSecurityCapability, ue.Get5GMMCapability(), nil, nil)
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
	mobileIdentity5GS = MobileIdentity5GS(
		[]uint8{0xf2, 0x02, 0xf8, 0x39, 0xca, 0xfe, 0x00, 0x00, 0x00, 0x00, 0x01})
	pdu = GetDeregistrationRequest(nasIE.AccessType_3gpp, 0, 0x04, mobileIdentity5GS)
	pdu, err = EncodeNasPduWithSecurity(ue, pdu, nasMessage.SecHdrTypeIntegrityProtectedAndCiphered, true, false)
	require.Nil(t, err)
	sendMsg, err = GetUplinkNASTransport(ue.AmfUeNgapId, ue.RanUeNgapId, pdu)
	require.Nil(t, err)
	_, err = n2Conn.Write(sendMsg)
	require.Nil(t, err)

	time.Sleep(500 * time.Millisecond)

	// receive Deregistration Accept
	n, err = n2Conn.Read(recvMsg)
	require.Nil(t, err)
	ngapPdu, err = ngapMessage.Parse(recvMsg[:n])
	require.Nil(t, err)
	require.True(t, ngapPdu.MessageType() == ngapMessage.MessageTypeInitiatingMessage &&
		ngapPdu.ProcedureCode() == ngapMessage.ProcedureCodeDownlinkNASTransport,
		"No DownlinkNASTransport received.")
	nasPdu = GetNasPdu(ue, ngapPdu.(*ngapMessage.DownlinkNASTransport))
	require.NotNil(t, nasPdu, "NAS PDU is nil")
	require.Equal(t, nasPdu.MsgType(), nasMessage.MsgTypeDeregAcceptUEOrig,
		"Received wrong GMM message. Expected Deregistration Accept.")

	// receive ngap UE Context Release Command
	n, err = n2Conn.Read(recvMsg)
	require.Nil(t, err)
	ngapPdu, err = ngapMessage.Parse(recvMsg[:n])
	require.Nil(t, err)
	require.True(t, ngapPdu.MessageType() == ngapMessage.MessageTypeInitiatingMessage &&
		ngapPdu.ProcedureCode() == ngapMessage.ProcedureCodeUEContextRelease,
		"No UEContextReleaseCommand received.")

	// send ngap UE Context Release Complete
	sendMsg, err = GetUEContextReleaseComplete(ue.AmfUeNgapId, ue.RanUeNgapId, nil)
	require.Nil(t, err)
	_, err = n2Conn.Write(sendMsg)
	require.Nil(t, err)

	time.Sleep(100 * time.Millisecond)
}
