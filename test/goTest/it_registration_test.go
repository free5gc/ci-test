package test

import (
	"bytes"
	"fmt"
	"io"
	"testing"
	"time"

	nasIE "github.com/free5gc/nas/ie"
	nasMessage "github.com/free5gc/nas/message"
	ngapMessage "github.com/free5gc/ngap/message"
	"github.com/free5gc/openapi/models"
	"github.com/stretchr/testify/require"
)

func TestRegistration(t *testing.T) {
	var (
		n       int
		sendMsg []byte
		recvMsg = make([]byte, 2048)
		err     error
	)

	// RAN connect to AMF
	n2Conn, err := connectToAmf(AMF_IP, IT_IP, AMF_PORT, IT_N2_PORT)
	require.NoError(t, err, "connect to AMF failed: %+v", err)
	defer n2Conn.Close()

	// send NGSetupRequest
	sendMsg, err = GetNGSetupRequest([]byte(IT_GNB_ID), 24, "free5GC")
	require.NoError(t, err, "get NGSetupRequest failed: %+v", err)
	_, err = n2Conn.Write(sendMsg)
	require.NoError(t, err, "send NGSetupRequest failed: %+v", err)

	// receive NGSetupResponse
	n, err = n2Conn.Read(recvMsg)
	require.NoError(t, err)
	ngapPdu, err := ngapMessage.Parse(recvMsg[:n])
	require.NoError(t, err)
	require.True(t, ngapPdu.MessageType() == ngapMessage.MessageTypeSuccessfulOutcome &&
		ngapPdu.ProcedureCode() == ngapMessage.ProcedureCodeNGSetup, "No NGSetupResponse received.")

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
	require.NoError(t, err)
	_, err = n2Conn.Write(sendMsg)
	require.NoError(t, err)

	// receive Authentication Request
	n, err = n2Conn.Read(recvMsg)
	require.NoError(t, err)
	ngapPdu, err = ngapMessage.Parse(recvMsg[:n])
	require.NoError(t, err)
	require.True(t, ngapPdu.MessageType() == ngapMessage.MessageTypeInitiatingMessage, "No NGAP Initiating Message received.")

	// Calcute for RES*
	require.IsType(t, (*ngapMessage.DownlinkNASTransport)(nil), ngapPdu)
	nasPdu := GetNasPdu(ue, ngapPdu.(*ngapMessage.DownlinkNASTransport))
	require.NotNil(t, nasPdu)
	require.Equal(t, nasMessage.MsgTypeAuthReq, nasPdu.MsgType(), "Received wrong GMM message. Expected Authentication Request.")
	rand := nasPdu.(*nasMessage.AuthReq).AuthParamRAND5GAuthChlg.Rand
	resStat := ue.DeriveRESstarAndSetKey(ue.AuthenticationSubs, rand[:], "5G:mnc093.mcc208.3gppnetwork.org")

	// send Authentication Response
	pdu := GetAuthenticationResponse(resStat, "")
	sendMsg, err = GetUplinkNASTransport(ue.AmfUeNgapId, ue.RanUeNgapId, pdu)
	require.NoError(t, err)
	_, err = n2Conn.Write(sendMsg)
	require.NoError(t, err)

	// receive Security Mode Command
	n, err = n2Conn.Read(recvMsg)
	require.NoError(t, err)
	ngapPdu, err = ngapMessage.Parse(recvMsg[:n])
	require.NoError(t, err)
	require.IsType(t, (*ngapMessage.DownlinkNASTransport)(nil), ngapPdu)
	nasPdu = GetNasPdu(ue, ngapPdu.(*ngapMessage.DownlinkNASTransport))
	require.NotNil(t, nasPdu)
	require.Equal(t, nasMessage.MsgTypeSecModeCmd, nasPdu.MsgType(), "Received wrong GMM message. Expected Security Mode Command.")

	// send Security Mode Complete
	registrationRequestWith5GMM := GetRegistrationRequest(
		nasIE.RegType_InitialReg, mobileIdentity5GS, nil, ueSecurityCapability, ue.Get5GMMCapability(), nil, nil)
	pdu = GetSecurityModeComplete(registrationRequestWith5GMM)
	pdu, err = EncodeNasPduWithSecurity(ue, pdu, nasMessage.SecHdrTypeIntegrityProtectedAndCipheredWithNew5gNasSecCtx, true, true)
	require.NoError(t, err)
	sendMsg, err = GetUplinkNASTransport(ue.AmfUeNgapId, ue.RanUeNgapId, pdu)
	require.NoError(t, err)
	_, err = n2Conn.Write(sendMsg)
	require.NoError(t, err)

	// receive ngap.InitialContextSetupRequest
	n, err = n2Conn.Read(recvMsg)
	require.NoError(t, err)
	ngapPdu, err = ngapMessage.Parse(recvMsg[:n])
	require.NoError(t, err)
	require.True(t, ngapPdu.MessageType() == ngapMessage.MessageTypeInitiatingMessage &&
		ngapPdu.ProcedureCode() == ngapMessage.ProcedureCodeInitialContextSetup, "No InitialContextSetup received.")

	setup := ngapPdu.(*ngapMessage.InitialContextSetupRequest)
	require.NotNil(t, setup.NASPDU)
	acceptPDU := setup.NASPDU.Value
	require.NotEmpty(t, acceptPDU)
	require.NotEqual(t, nasMessage.SecHdrTypePlainNas, nasMessage.GetSecHdrType(acceptPDU))
	accepted, err := nasMessage.Parse(acceptPDU, ue.NewSecCtx())
	require.NoError(t, err)
	require.IsType(t, (*nasMessage.RegAccept)(nil), accepted)

	// send InitialContextSetupResponse
	sendMsg, err = GetInitialContextSetupResponse(ue.AmfUeNgapId, ue.RanUeNgapId)
	require.NoError(t, err)
	_, err = n2Conn.Write(sendMsg)
	require.NoError(t, err)

	// Registration Accept may already be queued for retransmission when the
	// AMF receives Registration Complete. Consume the actual NAS exchange.
	require.NoError(t, completeRegistration(n2Conn, ue, acceptPDU))

	// send GetPduSessionEstablishmentRequest
	sNssai := models.Snssai{
		Sst: SST,
		Sd:  SD,
	}
	pdu = GetUlNasTransport_PduSessionEstablishmentRequest(10, nasIE.ReqType_InitialReq, "internet", &sNssai)
	pdu, err = EncodeNasPduWithSecurity(ue, pdu, nasMessage.SecHdrTypeIntegrityProtectedAndCiphered, true, false)
	require.NoError(t, err)
	sendMsg, err = GetUplinkNASTransport(ue.AmfUeNgapId, ue.RanUeNgapId, pdu)
	require.NoError(t, err)
	_, err = n2Conn.Write(sendMsg)
	require.NoError(t, err)

	// receive PDU session Resource Setup Request
	n, err = n2Conn.Read(recvMsg)
	require.NoError(t, err)
	ngapPdu, err = ngapMessage.Parse(recvMsg[:n])
	require.NoError(t, err)
	require.True(t, ngapPdu.MessageType() == ngapMessage.MessageTypeInitiatingMessage &&
		ngapPdu.ProcedureCode() == ngapMessage.ProcedureCodePDUSessionResourceSetup, "expected PDU session resource setup, got %T", ngapPdu)

	// send PDU session Resource Setup Response
	sendMsg, err = GetPDUSessionResourceSetupResponse(10, ue.AmfUeNgapId, ue.RanUeNgapId, IT_IP)
	require.NoError(t, err)
	_, err = n2Conn.Write(sendMsg)
	require.NoError(t, err)

	time.Sleep(1 * time.Second)
}

// completeRegistration acknowledges each Registration Accept and waits for
// the Configuration Update Command before starting a PDU session.
func completeRegistration(conn io.ReadWriter, ue *RanUeContext, lastAccept []byte) error {
	const maxRetransmissions = 4
	lastAccept = bytes.Clone(lastAccept)
	buf := make([]byte, 2048)
	if err := sendRegistrationComplete(conn, ue); err != nil {
		return err
	}
	for attempt := 0; attempt <= maxRetransmissions; attempt++ {
		n, err := conn.Read(buf)
		if err != nil {
			return err
		}
		msg, err := ngapMessage.Parse(buf[:n])
		if err != nil {
			return err
		}
		dl, ok := msg.(*ngapMessage.DownlinkNASTransport)
		if !ok {
			return fmt.Errorf("waiting for configuration update: unexpected NGAP %T", msg)
		}
		if dl.AMFUENGAPID == nil || dl.AMFUENGAPID.Value != ue.AmfUeNgapId ||
			dl.RANUENGAPID == nil || dl.RANUENGAPID.Value != ue.RanUeNgapId {
			return fmt.Errorf("downlink NAS transport for unexpected UE")
		}
		if dl.NASPDU == nil || len(dl.NASPDU.Value) == 0 {
			return fmt.Errorf("missing downlink NAS payload")
		}
		// A queued copy of the already verified NAS PDU has the same COUNT.
		// Discard it without advancing the security context a second time.
		if bytes.Equal(dl.NASPDU.Value, lastAccept) {
			continue
		}
		if nasMessage.GetSecHdrType(dl.NASPDU.Value) == nasMessage.SecHdrTypePlainNas {
			return fmt.Errorf("unprotected downlink NAS after registration")
		}
		nas, err := nasMessage.Parse(dl.NASPDU.Value, ue.NewSecCtx())
		if err != nil {
			return fmt.Errorf("decode downlink NAS: %w", err)
		}
		switch nas.(type) {
		case *nasMessage.CfgUpdateCmd:
			return nil
		case *nasMessage.RegAccept:
			// A freshly protected retransmission needs its own acknowledgement.
			lastAccept = bytes.Clone(dl.NASPDU.Value)
			if err := sendRegistrationComplete(conn, ue); err != nil {
				return err
			}
		default:
			return fmt.Errorf("waiting for configuration update: unexpected NAS %T", nas)
		}
	}
	return fmt.Errorf("configuration update missing: exceeded %d Registration Accept retransmissions", maxRetransmissions)
}

func sendRegistrationComplete(conn io.Writer, ue *RanUeContext) error {
	pdu, err := EncodeNasPduWithSecurity(ue, GetRegistrationComplete(nil),
		nasMessage.SecHdrTypeIntegrityProtectedAndCiphered, true, false)
	if err != nil {
		return err
	}
	ack, err := GetUplinkNASTransport(ue.AmfUeNgapId, ue.RanUeNgapId, pdu)
	if err != nil {
		return err
	}
	n, err := conn.Write(ack)
	if err != nil {
		return err
	}
	if n != len(ack) {
		return io.ErrShortWrite
	}
	return nil
}
