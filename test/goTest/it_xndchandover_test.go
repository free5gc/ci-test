package test

import (
	"net"
	"sync"
	"testing"
	"time"

	"github.com/free5gc/ngap/aper"
	nasIE "github.com/free5gc/nas/ie"
	nasMessage "github.com/free5gc/nas/message"
	ngapIE "github.com/free5gc/ngap/ie"
	ngapMessage "github.com/free5gc/ngap/message"
	"github.com/free5gc/openapi/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// waitForGTPEndMarkerDC waits, in parallel, for the GTP-U End Marker (8 bytes: version
// 1, message type 0xfe, zero length, then the old tunnel's TEID) that UPF sends on each
// old N3 tunnel after a path switch completes, confirming the old tunnels are actually
// retired rather than just assuming the switch worked because the ack looked right.
func waitForGTPEndMarkerDC(t *testing.T, mupfConn, supfConn *net.UDPConn) {
	wg := sync.WaitGroup{}
	wg.Add(2)

	go func() {
		defer wg.Done()
		recvMsg := make([]byte, 2048)
		n, err := mupfConn.Read(recvMsg)
		assert.Nil(t, err)
		assert.Equal(t, []byte{0x30, 0xfe, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01}, recvMsg[:n])
	}()

	go func() {
		defer wg.Done()
		recvMsg := make([]byte, 2048)
		n, err := supfConn.Read(recvMsg)
		assert.Nil(t, err)
		assert.Equal(t, []byte{0x30, 0xfe, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02}, recvMsg[:n])
	}()

	wg.Wait()
}

func TestXnDCHandover(t *testing.T) {
	var (
		n       int
		sendMsg []byte
		recvMsg = make([]byte, 2048)
		err     error
	)

	// Master RAN connect to AMF
	mranConn, err := connectToAmf(AMF_IP, IT_IP, AMF_PORT, IT_N2_PORT)
	require.Nil(t, err, "Master RAN connect to AMF failed: %+v", err)
	defer mranConn.Close()

	// Secondary RAN connect to AMF
	sranConn, err := connectToAmf(AMF_IP, IT_IP, AMF_PORT, IT_N2_PORT_2)
	require.Nil(t, err, "Secondary RAN connect to AMF failed: %+v", err)
	defer sranConn.Close()

	// Master RAN connect to UPF. Uses the standard GTP-U port 2152 on both ends, since
	// UPF always sends downlink replies there (not to an arbitrary local port).
	mupfConn, err := connectToUpf(IT_IP, UPF_IP, IT_N3_PORT, UPF_PORT)
	require.Nil(t, err, "Master RAN connect to UPF failed: %+v", err)
	defer mupfConn.Close()

	// Secondary RAN connect to UPF, via its own IP alias (IT_IP_2) so it can also bind
	// the standard port 2152 without conflicting with the master RAN's socket above.
	supfConn, err := connectToUpf(IT_IP_2, UPF_IP, IT_N3_PORT_2, UPF_PORT)
	require.Nil(t, err, "Secondary RAN connect to UPF failed: %+v", err)
	defer supfConn.Close()

	// Master RAN send NGSetupRequest
	sendMsg, err = GetNGSetupRequest([]byte(IT_GNB_ID), 24, "MasterRAN")
	assert.Nil(t, err)
	_, err = mranConn.Write(sendMsg)
	assert.Nil(t, err)

	// Master RAN receive NGSetupResponse
	n, err = mranConn.Read(recvMsg)
	assert.Nil(t, err)
	ngapPdu, err := ngapMessage.Parse(recvMsg[:n])
	assert.Nil(t, err)
	assert.True(t, ngapPdu.MessageType() == ngapMessage.MessageTypeSuccessfulOutcome &&
		ngapPdu.ProcedureCode() == ngapMessage.ProcedureCodeNGSetup,
		"No NGSetupResponse received from Master RAN.")

	// Secondary RAN send NGSetupRequest
	sendMsg, err = GetNGSetupRequest([]byte(IT_GNB_ID_2), 24, "SecondaryRAN")
	assert.Nil(t, err)
	_, err = sranConn.Write(sendMsg)
	assert.Nil(t, err)

	// Secondary RAN receive NGSetupResponse
	n, err = sranConn.Read(recvMsg)
	assert.Nil(t, err)
	ngapPdu, err = ngapMessage.Parse(recvMsg[:n])
	assert.Nil(t, err)
	assert.True(t, ngapPdu.MessageType() == ngapMessage.MessageTypeSuccessfulOutcome &&
		ngapPdu.ProcedureCode() == ngapMessage.ProcedureCodeNGSetup,
		"No NGSetupResponse received from Secondary RAN.")

	// New UE and initial registration via Master RAN
	ue := NewRanUeContext(UE_IMSI, 1, nasMessage.AlgCiphering128NEA0, nasMessage.AlgIntegrity128NIA2, models.AccessType_3_GPP_ACCESS)
	ue.AmfUeNgapId = 1
	ue.AuthenticationSubs = GetAuthSubscription(UE_K, UE_OPC, "")

	mobileIdentity5GS := MobileIdentity5GS(
		[]uint8{0x01, 0x02, 0xf8, 0x39, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10})
	ueSecurityCapability := ue.GetUESecurityCapability()
	registrationRequest := GetRegistrationRequest(
		nasIE.RegType_InitialReg, mobileIdentity5GS, nil, ueSecurityCapability, nil, nil, nil)
	sendMsg, err = GetInitialUEMessage(ue.RanUeNgapId, registrationRequest, "")
	assert.Nil(t, err)
	_, err = mranConn.Write(sendMsg)
	assert.Nil(t, err)

	// receive NAS Authentication Request
	n, err = mranConn.Read(recvMsg)
	assert.Nil(t, err)
	ngapPdu, err = ngapMessage.Parse(recvMsg[:n])
	assert.Nil(t, err)
	require.True(t, ngapPdu.MessageType() == ngapMessage.MessageTypeInitiatingMessage &&
		ngapPdu.ProcedureCode() == ngapMessage.ProcedureCodeDownlinkNASTransport,
		"No NAS Authentication Request received.")

	nasPdu := GetNasPdu(ue, ngapPdu.(*ngapMessage.DownlinkNASTransport))
	require.NotNil(t, nasPdu)
	require.Equal(t, nasPdu.MsgType(), nasMessage.MsgTypeAuthReq,
		"Received wrong GMM message. Expected Authentication Request.")
	rand := nasPdu.(*nasMessage.AuthReq).AuthParamRAND5GAuthChlg.Rand
	resStat := ue.DeriveRESstarAndSetKey(ue.AuthenticationSubs, rand[:], "5G:mnc093.mcc208.3gppnetwork.org")

	// send NAS Authentication Response
	pdu := GetAuthenticationResponse(resStat, "")
	sendMsg, err = GetUplinkNASTransport(ue.AmfUeNgapId, ue.RanUeNgapId, pdu)
	assert.Nil(t, err)
	_, err = mranConn.Write(sendMsg)
	assert.Nil(t, err)

	// receive NAS Security Mode Command
	n, err = mranConn.Read(recvMsg)
	assert.Nil(t, err)
	ngapPdu, err = ngapMessage.Parse(recvMsg[:n])
	assert.Nil(t, err)
	require.NotNil(t, ngapPdu)
	nasPdu = GetNasPdu(ue, ngapPdu.(*ngapMessage.DownlinkNASTransport))
	require.NotNil(t, nasPdu)
	require.Equal(t, nasPdu.MsgType(), nasMessage.MsgTypeSecModeCmd,
		"Received wrong GMM message. Expected Security Mode Command.")

	// send NAS Security Mode Complete
	registrationRequestWith5GMM := GetRegistrationRequest(nasIE.RegType_InitialReg,
		mobileIdentity5GS, nil, ueSecurityCapability, ue.Get5GMMCapability(), nil, nil)
	pdu = GetSecurityModeComplete(registrationRequestWith5GMM)
	pdu, err = EncodeNasPduWithSecurity(ue, pdu, nasMessage.SecHdrTypeIntegrityProtectedAndCipheredWithNew5gNasSecCtx, true, true)
	assert.Nil(t, err)
	sendMsg, err = GetUplinkNASTransport(ue.AmfUeNgapId, ue.RanUeNgapId, pdu)
	assert.Nil(t, err)
	_, err = mranConn.Write(sendMsg)
	assert.Nil(t, err)

	// receive ngap Initial Context Setup Request
	n, err = mranConn.Read(recvMsg)
	assert.Nil(t, err)
	ngapPdu, err = ngapMessage.Parse(recvMsg[:n])
	assert.Nil(t, err)
	require.True(t, ngapPdu.MessageType() == ngapMessage.MessageTypeInitiatingMessage &&
		ngapPdu.ProcedureCode() == ngapMessage.ProcedureCodeInitialContextSetup,
		"No InitialContextSetup received.")

	// send ngap Initial Context Setup Response
	sendMsg, err = GetInitialContextSetupResponse(ue.AmfUeNgapId, ue.RanUeNgapId)
	assert.Nil(t, err)
	_, err = mranConn.Write(sendMsg)
	assert.Nil(t, err)

	// send NAS Registration Complete
	pdu = GetRegistrationComplete(nil)
	pdu, err = EncodeNasPduWithSecurity(ue, pdu, nasMessage.SecHdrTypeIntegrityProtectedAndCiphered, true, false)
	assert.Nil(t, err)
	sendMsg, err = GetUplinkNASTransport(ue.AmfUeNgapId, ue.RanUeNgapId, pdu)
	assert.Nil(t, err)
	_, err = mranConn.Write(sendMsg)
	assert.Nil(t, err)

	// receive UE Configuration Update Command (equivalent to recvUeConfigUpdateCmd in reference test)
	n, err = mranConn.Read(recvMsg)
	assert.Nil(t, err)
	ngapPdu, err = ngapMessage.Parse(recvMsg[:n])
	assert.Nil(t, err)
	assert.Equal(t, ngapPdu.MessageType(), ngapMessage.MessageTypeInitiatingMessage, "Not MessageTypeInitiatingMessage")
	assert.Equal(t, ngapPdu.ProcedureCode(), ngapMessage.ProcedureCodeDownlinkNASTransport, "Not ProcedureCodeDownlinkNASTransport")

	time.Sleep(100 * time.Millisecond)

	// ============================================
	// PDU Session Establishment with DC: master and secondary RAN both get a QoS flow
	// mapping from the start (unlike TestDynamicDC, which enables DC later via Modify
	// Indication).
	// ============================================
	sNssai := models.Snssai{
		Sst: SST,
		Sd:  SD,
	}
	pdu = GetUlNasTransport_PduSessionEstablishmentRequest(10, nasIE.ReqType_InitialReq, "internet", &sNssai)
	pdu, err = EncodeNasPduWithSecurity(ue, pdu, nasMessage.SecHdrTypeIntegrityProtectedAndCiphered, true, false)
	assert.Nil(t, err)
	sendMsg, err = GetUplinkNASTransport(ue.AmfUeNgapId, ue.RanUeNgapId, pdu)
	assert.Nil(t, err)
	_, err = mranConn.Write(sendMsg)
	assert.Nil(t, err)

	// receive ngap PDU Session Resource Setup Request
	n, err = mranConn.Read(recvMsg)
	assert.Nil(t, err)
	ngapPdu, err = ngapMessage.Parse(recvMsg[:n])
	assert.Nil(t, err)
	require.True(t, ngapPdu.MessageType() == ngapMessage.MessageTypeInitiatingMessage &&
		ngapPdu.ProcedureCode() == ngapMessage.ProcedureCodePDUSessionResourceSetup,
		"No PDU Session Resource Setup Request received.")

	// send ngap PDU Session Resource Setup Response with DC (splits QoS flow to master + secondary RAN)
	mranDlTeid := "\x00\x00\x00\x01"
	sranDlTeid := "\x00\x00\x00\x02"
	sendMsg, err = GetPDUSessionResourceSetupResponseWithDC(10, ue.AmfUeNgapId, ue.RanUeNgapId, mranDlTeid, sranDlTeid)
	assert.Nil(t, err)
	_, err = mranConn.Write(sendMsg)
	assert.Nil(t, err)

	time.Sleep(1 * time.Second)

	// ping test via master and secondary RAN before handover
	t.Run("ping test via master RAN", func(t *testing.T) {
		icmpTestDC(t, mupfConn, "00000002", EIGHT_IP, false)
	})
	t.Run("ping test via secondary RAN", func(t *testing.T) {
		icmpTestDC(t, supfConn, "00000003", ONE_IP, false)
	})

	// ============================================
	// Xn handover with DC: master RAN hands over to secondary RAN, meaning secondary
	// RAN becomes the new master and master RAN becomes the new secondary. The
	// secondary RAN's connection (sranConn) initiates the Path Switch Request since
	// it's now acting as the new master.
	// ============================================
	newMranDlTeid := "\x00\x00\x00\x03"
	newSranDlTeid := "\x00\x00\x00\x04"
	sendMsg, err = GetPathSwitchRequestWithDC(10, ue.AmfUeNgapId, ue.RanUeNgapId, newMranDlTeid, newSranDlTeid)
	require.Nil(t, err)
	_, err = sranConn.Write(sendMsg)
	require.Nil(t, err)

	// receive Path Switch Request Acknowledge from the new master RAN (sranConn)
	n, err = sranConn.Read(recvMsg)
	require.Nil(t, err)
	ngapPdu, err = ngapMessage.Parse(recvMsg[:n])
	require.Nil(t, err)
	require.True(t, ngapPdu.MessageType() == ngapMessage.MessageTypeSuccessfulOutcome &&
		ngapPdu.ProcedureCode() == ngapMessage.ProcedureCodePathSwitchRequest,
		"No PathSwitchRequestAcknowledge received.")

	// verify the acknowledge carries the expected UL TEIDs for the new master (from the
	// main transfer) and new secondary (from the AdditionalNGUUPTNLInformation extension)
	ack, ok := ngapPdu.(*ngapMessage.PathSwitchRequestAcknowledge)
	require.True(t, ok)
	require.NotNil(t, ack.PDUSessionResourceSwitchedList)
	for _, item := range ack.PDUSessionResourceSwitchedList.List {
		var transfer ngapIE.PathSwitchRequestAcknowledgeTransfer
		err = ngapIE.UnmarshalBinary([]byte(*item.PathSwitchRequestAcknowledgeTransfer), &transfer)
		require.Nil(t, err)

		ulTunnel := transfer.ULNGUUPTNLInformation.Choice.(*ngapIE.GTPTunnel)
		assert.Equal(t, aper.OctetString("\x00\x00\x00\x02"), ulTunnel.GTPTEID.Value,
			"unexpected UL TEID for new master RAN")

		if transfer.IEExtensions != nil {
			for _, ieExt := range transfer.IEExtensions.List {
				if ieExt.Id.Value == ngapIE.ProtocolIEIDAdditionalNGUUPTNLInformation {
					additionalUlInfo := ieExt.AdditionalNGUUPTNLInformation.List[0].ULNGUUPTNLInformation
					additionalTunnel := additionalUlInfo.Choice.(*ngapIE.GTPTunnel)
					assert.Equal(t, aper.OctetString("\x00\x00\x00\x03"), additionalTunnel.GTPTEID.Value,
						"unexpected UL TEID for new secondary RAN")
				}
			}
		}
	}

	// After the path switch, UPF sends a GTP End Marker on each old tunnel to signal
	// they're retired.
	waitForGTPEndMarkerDC(t, mupfConn, supfConn)

	// ping test via new master RAN (original secondary RAN's socket) and new secondary
	// RAN (original master RAN's socket) after handover
	t.Run("ping test via new master RAN (original secondary RAN)", func(t *testing.T) {
		icmpTestDC(t, supfConn, "00000002", EIGHT_IP, false)
	})
	t.Run("ping test via new secondary RAN (original master RAN)", func(t *testing.T) {
		icmpTestDC(t, mupfConn, "00000003", ONE_IP, false)
	})
}
