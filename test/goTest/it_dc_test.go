package test

import (
	"encoding/hex"
	"fmt"
	"net"
	"testing"
	"time"

	nasIE "github.com/free5gc/nas/ie"
	nasMessage "github.com/free5gc/nas/message"
	ngapMessage "github.com/free5gc/ngap/message"
	"github.com/free5gc/openapi/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

// icmpTestDC sends a GTP-encapsulated ICMP echo request over upfConn (uplink, tagged
// with ulTeid) toward destIp and asserts on whether a reply is read back within 2s.
// Used to verify a PDU session's QoS flow is actually delivering traffic through a
// specific RAN's N3 tunnel (master or secondary) after a dual-connectivity setup.
func icmpTestDC(t *testing.T, upfConn *net.UDPConn, ulTeid, destIp string, expectedError bool) {
	gtpHdr, err := hex.DecodeString(fmt.Sprintf("32ff0034%s00000000", ulTeid))
	assert.Nil(t, err)
	icmpData, err := hex.DecodeString("8c870d0000000000101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f3031323334353637")
	assert.Nil(t, err)

	// UE's PDU session IP is dynamically allocated by SMF from the 10.60.0.0/16 pool
	// (not observed here) and hardcoded below to match the reference test's assumption
	// of the first address in the pool; if this fails, check the allocated IP (PDU
	// Address IE in the PDU Session Establishment Accept) against this value.
	ueIp := "10.60.0.1"

	ipv4hdr := ipv4.Header{
		Version:  4,
		Len:      20,
		Protocol: 1,
		Flags:    0,
		TotalLen: 48,
		TTL:      64,
		Src:      net.ParseIP(ueIp).To4(),
		Dst:      net.ParseIP(destIp).To4(),
		ID:       1,
	}
	checksum := CalculateIpv4HeaderChecksum(&ipv4hdr)
	ipv4hdr.Checksum = int(checksum)

	v4HdrBuf, err := ipv4hdr.Marshal()
	assert.Nil(t, err)
	tt := append(gtpHdr, v4HdrBuf...)

	m := icmp.Message{
		Type: ipv4.ICMPTypeEcho, Code: 0,
		Body: &icmp.Echo{
			ID: 12394, Seq: 1,
			Data: icmpData,
		},
	}
	b, err := m.Marshal(nil)
	assert.Nil(t, err)
	b[2] = 0xaf
	b[3] = 0x88
	_, err = upfConn.Write(append(tt, b...))
	assert.Nil(t, err)

	recvMsg := make([]byte, 2048)
	err = upfConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	assert.Nil(t, err)
	n, err := upfConn.Read(recvMsg)
	if expectedError {
		assert.NotNil(t, err)
	} else {
		assert.Nil(t, err)
		assert.Equal(t, 64, n)
	}
	err = upfConn.SetReadDeadline(time.Time{})
	assert.Nil(t, err)
}

func TestDC(t *testing.T) {
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
	// PDU Session Establishment with DC: master RAN sends the request, but the
	// response's QoS flow is split to deliver downlink traffic through both master
	// and secondary RAN simultaneously (AdditionalDLQosFlowPerTNLInformation).
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

	// ping test via master RAN
	t.Run("ping test via master RAN", func(t *testing.T) {
		icmpTestDC(t, mupfConn, "00000002", EIGHT_IP, false)
	})

	// ping test via secondary RAN
	t.Run("ping test via secondary RAN", func(t *testing.T) {
		icmpTestDC(t, supfConn, "00000003", ONE_IP, false)
	})
}
