package test

import (
	cryptorand "crypto/rand"
	"encoding/hex"
	"testing"
	"time"

	"github.com/free5gc/nas"
	"github.com/free5gc/nas/nasMessage"
	"github.com/free5gc/nas/nasType"
	"github.com/free5gc/nas/security"
	"github.com/free5gc/ngap"
	"github.com/free5gc/ngap/ngapType"
	"github.com/free5gc/openapi/models"
	"github.com/free5gc/util/milenage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestReSynchronization(t *testing.T) {
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
	_, err = ngap.Decoder(recvMsg[:n])
	assert.Nil(t, err)

	// New UE
	ue := NewRanUeContext(UE_IMSI, 1, security.AlgCiphering128NEA0, security.AlgIntegrity128NIA2, models.AccessType__3_GPP_ACCESS)
	ue.AmfUeNgapId = 1
	ue.AuthenticationSubs = GetAuthSubscription(UE_K, UE_OPC, "")

	// send InitialUeMessage(Registration Request)
	mobileIdentity5GS := nasType.MobileIdentity5GS{
		Len:    13, // suci
		Buffer: []uint8{0x01, 0x02, 0xf8, 0x39, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10},
	}
	ueSecurityCapability := ue.GetUESecurityCapability()
	registrationRequest := GetRegistrationRequest(
		nasMessage.RegistrationType5GSInitialRegistration, mobileIdentity5GS, nil, ueSecurityCapability, nil, nil, nil)
	sendMsg, err = GetInitialUEMessage(ue.RanUeNgapId, registrationRequest, "")
	assert.Nil(t, err)
	_, err = n2Conn.Write(sendMsg)
	assert.Nil(t, err)

	// receive NAS Authentication Request
	n, err = n2Conn.Read(recvMsg)
	assert.Nil(t, err)
	ngapMsg, err := ngap.Decoder(recvMsg[:n])
	assert.Nil(t, err)

	nasPdu := GetNasPdu(ue, ngapMsg.InitiatingMessage.Value.DownlinkNASTransport)
	require.NotNil(t, nasPdu)
	require.NotNil(t, nasPdu.GmmMessage, "GMM message is nil")
	require.Equal(t, nasPdu.GmmHeader.GetMessageType(), nas.MsgTypeAuthenticationRequest,
		"Received wrong GMM message. Expected Authentication Request.")

	// gen AK
	K, err := hex.DecodeString(ue.AuthenticationSubs.EncPermanentKey)
	assert.Nil(t, err)
	OPC, err := hex.DecodeString(ue.AuthenticationSubs.EncOpcKey)
	assert.Nil(t, err)
	rand := nasPdu.AuthenticationRequest.GetRANDValue()

	// Based on TS 33.105, clause 5.1.1.3. The SQN_ms is a SQN value managed by the mobile station (or UE).
	// Whenever the UE finds that SQN_ms is not in synced with SQN sent by the AMF, it start the
	// re-synchronization process, sending AUTS (Authentication Token for Synchronization) to the
	// AMF. AUTS is concatenation of concealed SQN_ms and MAC_S.
	// AUTS = SQN_ms [^ AK*] | MAC-S

	// To test out that core network synchronize the SQN properly. We generated a random SQN here.
	var randomSqnMs [6]byte
	_, err = cryptorand.Read(randomSqnMs[:])
	assert.Nil(t, err)

	// Build AUTS using the library function which correctly implements:
	// AUTS = (SQNms ⊕ AK*) || MAC-S
	// where AK* = f5*(K, RAND) and MAC-S = f1*(K, SQNms, RAND, AMF=0x0000)
	AUTS, err := milenage.GenerateAUTS(OPC, K, rand[:], randomSqnMs[:])
	assert.Nil(t, err)

	// send NAS Authentication Failure (Synch failure)
	pdu := GetAuthenticationFailure(nasMessage.Cause5GMMSynchFailure, AUTS)
	sendMsg, err = GetUplinkNASTransport(ue.AmfUeNgapId, ue.RanUeNgapId, pdu)
	assert.Nil(t, err)
	_, err = n2Conn.Write(sendMsg)
	assert.Nil(t, err)

	// receive NAS Authentication Request (re-synchronized)
	n, err = n2Conn.Read(recvMsg)
	assert.Nil(t, err)
	ngapMsg, err = ngap.Decoder(recvMsg[:n])
	assert.Nil(t, err)

	nasPdu = GetNasPdu(ue, ngapMsg.InitiatingMessage.Value.DownlinkNASTransport)
	require.NotNil(t, nasPdu)
	require.NotNil(t, nasPdu.GmmMessage, "GMM message is nil")
	require.Equal(t, nasPdu.GmmHeader.GetMessageType(), nas.MsgTypeAuthenticationRequest,
		"Received wrong GMM message. Expected Authentication Request.")
	rand = nasPdu.AuthenticationRequest.GetRANDValue()

	// After re-synchronization, check if the SQN is updated
	// Use AK (from f5, not f5*) to de-conceal SQN from AUTN
	autn := nasPdu.AuthenticationRequest.GetAUTN()
	SQN, _, _, _, _, err := milenage.GenerateKeysWithAUTN(OPC, K, rand[:], autn[:])
	assert.Nil(t, err)
	ue.AuthenticationSubs.SequenceNumber.Sqn = hex.EncodeToString(SQN)
	resStar := ue.DeriveRESstarAndSetKey(ue.AuthenticationSubs, rand[:], "5G:mnc093.mcc208.3gppnetwork.org")

	// send NAS Authentication Response
	pdu = GetAuthenticationResponse(resStar, "")
	sendMsg, err = GetUplinkNASTransport(ue.AmfUeNgapId, ue.RanUeNgapId, pdu)
	assert.Nil(t, err)
	_, err = n2Conn.Write(sendMsg)
	assert.Nil(t, err)

	// receive NAS Security Mode Command
	n, err = n2Conn.Read(recvMsg)
	assert.Nil(t, err)
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
		mobileIdentity5GS, nil, ueSecurityCapability, ue.Get5GMMCapability(), nil, nil)
	pdu = GetSecurityModeComplete(registrationRequestWith5GMM)
	pdu, err = EncodeNasPduWithSecurity(ue, pdu, nas.SecurityHeaderTypeIntegrityProtectedAndCipheredWithNew5gNasSecurityContext, true, true)
	assert.Nil(t, err)
	sendMsg, err = GetUplinkNASTransport(ue.AmfUeNgapId, ue.RanUeNgapId, pdu)
	assert.Nil(t, err)
	_, err = n2Conn.Write(sendMsg)
	assert.Nil(t, err)

	// receive ngap Initial Context Setup Request
	n, err = n2Conn.Read(recvMsg)
	assert.Nil(t, err)
	_, err = ngap.Decoder(recvMsg[:n])
	assert.Nil(t, err)

	// send ngap Initial Context Setup Response
	sendMsg, err = GetInitialContextSetupResponse(ue.AmfUeNgapId, ue.RanUeNgapId)
	assert.Nil(t, err)
	_, err = n2Conn.Write(sendMsg)
	assert.Nil(t, err)

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

	time.Sleep(100 * time.Millisecond)

	// send PduSessionEstablishmentRequest
	sNssai := models.Snssai{
		Sst: SST,
		Sd:  SD,
	}
	pdu = GetUlNasTransport_PduSessionEstablishmentRequest(10, nasMessage.ULNASTransportRequestTypeInitialRequest, "internet", &sNssai)
	pdu, err = EncodeNasPduWithSecurity(ue, pdu, nas.SecurityHeaderTypeIntegrityProtectedAndCiphered, true, false)
	assert.Nil(t, err)
	sendMsg, err = GetUplinkNASTransport(ue.AmfUeNgapId, ue.RanUeNgapId, pdu)
	assert.Nil(t, err)
	_, err = n2Conn.Write(sendMsg)
	assert.Nil(t, err)

	// receive NGAP PDU Session Resource Setup Request (DL NAS transport / PDU Session Establishment Accept)
	n, err = n2Conn.Read(recvMsg)
	assert.Nil(t, err)
	_, err = ngap.Decoder(recvMsg[:n])
	assert.Nil(t, err)

	// send NGAP PDU Session Resource Setup Response
	sendMsg, err = GetPDUSessionResourceSetupResponse(10, ue.AmfUeNgapId, ue.RanUeNgapId, IT_IP)
	assert.Nil(t, err)
	_, err = n2Conn.Write(sendMsg)
	assert.Nil(t, err)

	time.Sleep(1 * time.Second)
}
