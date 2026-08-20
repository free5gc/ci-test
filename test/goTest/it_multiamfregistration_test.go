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

func TestMultiAmfRegistration(t *testing.T) {
	time.Sleep(3 * time.Second)

	var (
		n       int
		sendMsg []byte
		recvMsg = make([]byte, 2048)
		err     error
	)

	// RAN connect to old AMF
	conn, err := connectToAmf(AMF_IP, IT_IP, AMF_PORT, IT_N2_PORT)
	assert.Nil(t, err, "connect to AMF failed: %+v", err)

	// send NGSetupRequest
	sendMsg, err = GetNGSetupRequest([]byte(IT_GNB_ID), 24, "free5GC")
	assert.Nil(t, err)
	_, err = conn.Write(sendMsg)
	assert.Nil(t, err)

	// receive NGSetupResponse
	n, err = conn.Read(recvMsg)
	assert.Nil(t, err)
	ngapPdu, err := ngapMessage.Parse(recvMsg[:n])
	assert.Nil(t, err)
	assert.True(t, ngapPdu.MessageType() == ngapMessage.MessageTypeSuccessfulOutcome &&
		ngapPdu.ProcedureCode() == ngapMessage.ProcedureCodeNGSetup,
		"No NGSetupResponse received.")

	// RAN connect to new AMF
	conn2, err := connectToAmf(AMF_2_IP, IT_IP, AMF_PORT, IT_N2_PORT+1)
	assert.Nil(t, err, "connect to AMF2 failed: %+v", err)
	defer conn2.Close()

	// send NGSetupRequest to new AMF
	sendMsg, err = GetNGSetupRequest([]byte(IT_GNB_ID), 24, "free5GC")
	assert.Nil(t, err)
	_, err = conn2.Write(sendMsg)
	assert.Nil(t, err)

	// receive NGSetupResponse from new AMF
	n, err = conn2.Read(recvMsg)
	assert.Nil(t, err)
	ngapPdu, err = ngapMessage.Parse(recvMsg[:n])
	assert.Nil(t, err)
	assert.True(t, ngapPdu.MessageType() == ngapMessage.MessageTypeSuccessfulOutcome &&
		ngapPdu.ProcedureCode() == ngapMessage.ProcedureCodeNGSetup,
		"No NGSetupResponse received from AMF2.")

	// New UE with NEA2 to match multi-AMF registration security context behavior
	ue := NewRanUeContext(UE_IMSI, 1, nasMessage.AlgCiphering128NEA2, nasMessage.AlgIntegrity128NIA2, models.AccessType_3_GPP_ACCESS)
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
	_, err = conn.Write(sendMsg)
	require.Nil(t, err)

	// receive NAS Authentication Request
	n, err = conn.Read(recvMsg)
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
	_, err = conn.Write(sendMsg)
	require.Nil(t, err)

	// receive NAS Security Mode Command
	n, err = conn.Read(recvMsg)
	require.Nil(t, err)
	ngapPdu, err = ngapMessage.Parse(recvMsg[:n])
	require.Nil(t, err)
	require.NotNil(t, ngapPdu)
	nasPdu = GetNasPdu(ue, ngapPdu.(*ngapMessage.DownlinkNASTransport))
	require.NotNil(t, nasPdu)
	require.Equal(t, nasPdu.MsgType(), nasMessage.MsgTypeSecModeCmd, "Received wrong GMM message. Expected Security Mode Command.")

	// send NAS Security Mode Complete
	registrationRequestWith5GMM := GetRegistrationRequest(nasIE.RegType_InitialReg,
		mobileIdentity5GS, nil, ueSecurityCapability, ue.Get5GMMCapability(), nil, nil)
	pdu = GetSecurityModeComplete(registrationRequestWith5GMM)
	pdu, err = EncodeNasPduWithSecurity(ue, pdu, nasMessage.SecHdrTypeIntegrityProtectedAndCipheredWithNew5gNasSecCtx, true, true)
	require.Nil(t, err)
	sendMsg, err = GetUplinkNASTransport(ue.AmfUeNgapId, ue.RanUeNgapId, pdu)
	require.Nil(t, err)
	_, err = conn.Write(sendMsg)
	require.Nil(t, err)

	// receive ngap Initial Context Setup Request — extract GUTI from NAS PDU
	n, err = conn.Read(recvMsg)
	require.Nil(t, err)
	ngapPdu, err = ngapMessage.Parse(recvMsg[:n])
	require.Nil(t, err)
	assert.True(t, ngapPdu.MessageType() == ngapMessage.MessageTypeInitiatingMessage &&
		ngapPdu.ProcedureCode() == ngapMessage.ProcedureCodeInitialContextSetup,
		"No InitialContextSetup received.")

	initialContextSetup, ok := ngapPdu.(*ngapMessage.InitialContextSetupRequest)
	require.True(t, ok)
	require.NotNil(t, initialContextSetup.NASPDU, "Initial Context Setup Request has no NAS PDU")
	payload := []byte(initialContextSetup.NASPDU.Value)
	m, err := NASDecode(ue, nasMessage.GetSecHdrType(payload), payload)
	assert.Nil(t, err)
	regAccept, ok := m.(*nasMessage.RegAccept)
	require.True(t, ok, "Initial Context Setup Request NAS PDU is not a Registration Accept")
	guti := regAccept.GUTI5G
	require.NotNil(t, guti, "GUTI not found in Initial Context Setup Request NAS PDU")

	// send ngap Initial Context Setup Response
	sendMsg, err = GetInitialContextSetupResponse(ue.AmfUeNgapId, ue.RanUeNgapId)
	require.Nil(t, err)
	_, err = conn.Write(sendMsg)
	require.Nil(t, err)

	// send NAS Registration Complete
	pdu = GetRegistrationComplete(nil)
	pdu, err = EncodeNasPduWithSecurity(ue, pdu, nasMessage.SecHdrTypeIntegrityProtectedAndCiphered, true, false)
	require.Nil(t, err)
	sendMsg, err = GetUplinkNASTransport(ue.AmfUeNgapId, ue.RanUeNgapId, pdu)
	require.Nil(t, err)
	_, err = conn.Write(sendMsg)
	require.Nil(t, err)

	time.Sleep(1 * time.Second)

	conn.Close()

	// ----- Second registration: UE re-registers with GUTI directly on the new AMF -----
	// Unlike TestNasReroute (which requests an explicit S-NSSAI to force AMF reselection/reroute),
	// this registration omits Requested NSSAI so the new AMF, sharing the same AMF Set as the old
	// AMF, recognizes the GUTI and completes registration directly instead of rerouting.

	// inner registration request: integrity + cipher (existing security context from first registration)
	innerRegistrationRequest := GetRegistrationRequest(nasIE.RegType_InitialReg,
		guti, nil, ue.GetUESecurityCapability(), ue.Get5GMMCapability(), nil, nil)
	pdu, err = EncodeNasPduWithSecurity(ue, innerRegistrationRequest, nasMessage.SecHdrTypeIntegrityProtectedAndCiphered, true, false)
	require.Nil(t, err)

	// outer registration request: integrity protected only, contains inner as NAS message container
	registrationRequest = GetRegistrationRequest(nasIE.RegType_InitialReg,
		guti, nil, ueSecurityCapability, ue.Get5GMMCapability(), pdu, nil)
	pdu, err = EncodeNasPduWithSecurity(ue, registrationRequest, nasMessage.SecHdrTypeIntegrityProtected, true, false)
	require.Nil(t, err)
	sendMsg, err = GetInitialUEMessage(ue.RanUeNgapId, pdu, "fe0000000001")
	require.Nil(t, err)

	_, err = conn2.Write(sendMsg)
	require.Nil(t, err)

	// receive ngap Initial Context Setup Request from new AMF (direct completion, no reroute)
	n, err = conn2.Read(recvMsg)
	require.Nil(t, err)
	ngapPdu, err = ngapMessage.Parse(recvMsg[:n])
	require.Nil(t, err)
	assert.True(t, ngapPdu.MessageType() == ngapMessage.MessageTypeInitiatingMessage &&
		ngapPdu.ProcedureCode() == ngapMessage.ProcedureCodeInitialContextSetup,
		"No InitialContextSetup received.")

	// send ngap Initial Context Setup Response
	sendMsg, err = GetInitialContextSetupResponse(ue.AmfUeNgapId, ue.RanUeNgapId)
	require.Nil(t, err)
	_, err = conn2.Write(sendMsg)
	require.Nil(t, err)

	// ue send NAS Registration Complete
	pdu = GetRegistrationComplete(nil)
	pdu, err = EncodeNasPduWithSecurity(ue, pdu, nasMessage.SecHdrTypeIntegrityProtectedAndCiphered, true, false)
	assert.Nil(t, err)
	sendMsg, err = GetUplinkNASTransport(ue.AmfUeNgapId, ue.RanUeNgapId, pdu)
	assert.Nil(t, err)
	_, err = conn2.Write(sendMsg)
	assert.Nil(t, err)

	time.Sleep(1 * time.Second)
}
