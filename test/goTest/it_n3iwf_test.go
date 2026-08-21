package test

import (
	"encoding/binary"
	"fmt"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/davecgh/go-spew/spew"
	"github.com/go-ping/ping"
	"github.com/stretchr/testify/assert"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"github.com/free5gc/ike"
	eap "github.com/free5gc/ike/eap"
	ike_message "github.com/free5gc/ike/message"
	ike_security "github.com/free5gc/ike/security"
	"github.com/free5gc/ike/security/dh"
	"github.com/free5gc/ike/security/encr"
	"github.com/free5gc/ike/security/integ"
	"github.com/free5gc/ike/security/prf"

	nasIE "github.com/free5gc/nas/ie"
	nasMessage "github.com/free5gc/nas/message"
	"github.com/free5gc/openapi/models"
)

// TestNon3GPPUE simulates a full non-3GPP-access UE talking to N3IWF: IKE_SA_INIT,
// IKE_AUTH with EAP-5G-encapsulated NAS (Registration Request through Security Mode
// Complete), IPsec child SA + XFRM interface setup, NAS Registration Complete and PDU
// Session Establishment over the resulting NAS-over-TCP connection, and a GRE tunnel
// per PDU session carrying user-plane traffic — then verifies actual connectivity with
// a real ping.
//
// Unlike the reference test's bare-metal veth-pair topology, this container only has
// one NIC (see const.go IT_IPSEC_IFACE_NAME/IT_IP/N3IWF_IP), so the XFRM interfaces are
// built on top of it directly.
func TestN3iwf(t *testing.T) {
	// New UE
	ue := NewRanUeContext(UE_IMSI, 1, nasMessage.AlgCiphering128NEA0, nasMessage.AlgIntegrity128NIA2,
		models.AccessType_NON_3_GPP_ACCESS)
	ue.AmfUeNgapId = 1
	ue.AuthenticationSubs = GetAuthSubscription(UE_K, UE_OPC, "")
	mobileIdentity5GS := MobileIdentity5GS(
		[]uint8{0x01, 0x02, 0xf8, 0x39, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10})

	// Used to save IPsec/IKE related data
	n3ue := new(N3IWFUe)
	n3ue.N3IWFChildSecurityAssociation = make(map[uint32]*ChildSecurityAssociation)
	n3ue.TemporaryExchangeMsgIDChildSAMapping = make(map[uint32]*ChildSecurityAssociation)

	n3iwfUDPAddr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", N3IWF_IP, N3IWF_IKE_PORT))
	if err != nil {
		t.Fatalf("Resolve UDP address %s:%d fail: %+v", N3IWF_IP, N3IWF_IKE_PORT, err)
	}
	udpConnection, err := setupUDPSocket()
	if err != nil {
		t.Fatalf("Setup UDP socket Fail: %+v", err)
	}

	// ============================================
	// IKE_SA_INIT
	// ============================================
	ikeInitiatorSPI := uint64(123123)
	payload := new(ike_message.IKEPayloadContainer)

	// Security Association
	securityAssociation := payload.BuildSecurityAssociation()
	// Proposal 1
	proposal := securityAssociation.Proposals.BuildProposal(1, ike_message.TypeIKE, nil)
	// ENCR
	var attributeType uint16 = ike_message.AttributeTypeKeyLength
	var keyLength uint16 = 256
	proposal.EncryptionAlgorithm.BuildTransform(ike_message.TypeEncryptionAlgorithm, ike_message.ENCR_AES_CBC, &attributeType, &keyLength, nil)
	// INTEG
	proposal.IntegrityAlgorithm.BuildTransform(ike_message.TypeIntegrityAlgorithm, ike_message.AUTH_HMAC_SHA1_96, nil, nil, nil)
	// PRF
	proposal.PseudorandomFunction.BuildTransform(ike_message.TypePseudorandomFunction, ike_message.PRF_HMAC_SHA1, nil, nil, nil)
	// DH
	proposal.DiffieHellmanGroup.BuildTransform(ike_message.TypeDiffieHellmanGroup, ike_message.DH_2048_BIT_MODP, nil, nil, nil)

	// Key exchange data
	generator := new(big.Int).SetUint64(dh.Group14Generator)
	factor, ok := new(big.Int).SetString(dh.Group14PrimeString, 16)
	if !ok {
		t.Fatalf("Generate key exchange data failed")
	}
	secert, err := ike_security.GenerateRandomNumber()
	if err != nil {
		t.Fatalf("Generate secert: %v", err)
	}
	localPublicKeyExchangeValue := new(big.Int).Exp(generator, secert, factor).Bytes()
	prependZero := make([]byte, len(factor.Bytes())-len(localPublicKeyExchangeValue))
	localPublicKeyExchangeValue = append(prependZero, localPublicKeyExchangeValue...)
	payload.BuildKeyExchange(ike_message.DH_2048_BIT_MODP, localPublicKeyExchangeValue)

	// Nonce
	localNonceBigInt, err := ike_security.GenerateRandomNumber()
	if err != nil {
		t.Fatalf("Generate localNonce : %v", err)
	}
	localNonce := localNonceBigInt.Bytes()
	payload.BuildNonce(localNonce)

	ikeMessage := ike_message.NewMessage(ikeInitiatorSPI, 0, ike_message.IKE_SA_INIT,
		false, true, 0, *payload)
	// Send to N3IWF
	ikeMessageData, err := ike.EncodeEncrypt(ikeMessage, nil, ike_message.Role_Initiator)
	if err != nil {
		t.Fatalf("Encode IKE Message fail: %+v", err)
	}
	if _, err := udpConnection.WriteToUDP(ikeMessageData, n3iwfUDPAddr); err != nil {
		t.Fatalf("Write IKE maessage fail: %+v", err)
	}
	realMessage1, _ := ikeMessage.Encode()
	ikeSecurityAssociation := &IKESecurityAssociation{
		ResponderSignedOctets: realMessage1,
	}

	// Receive N3IWF reply
	buffer := make([]byte, 65535)
	n, _, err := udpConnection.ReadFromUDP(buffer)
	if err != nil {
		t.Fatalf("Read IKE Message fail: %+v", err)
	}
	ikeMessage.Payloads.Reset()
	err = ikeMessage.Decode(buffer[:n])
	if err != nil {
		t.Fatalf("Decode IKE Message fail: %+v", err)
	}

	var sharedKeyExchangeData []byte
	var remoteNonce []byte

	for _, ikePayload := range ikeMessage.Payloads {
		switch ikePayload.Type() {
		case ike_message.TypeSA:
			t.Log("Get SA payload")
		case ike_message.TypeKE:
			remotePublicKeyExchangeValue := ikePayload.(*ike_message.KeyExchange).KeyExchangeData
			var i = 0
			for remotePublicKeyExchangeValue[i] == 0 {
			}
			remotePublicKeyExchangeValue = remotePublicKeyExchangeValue[i:]
			remotePublicKeyExchangeValueBig := new(big.Int).SetBytes(remotePublicKeyExchangeValue)
			sharedKeyExchangeData = new(big.Int).Exp(remotePublicKeyExchangeValueBig, secert, factor).Bytes()
		case ike_message.TypeNiNr:
			remoteNonce = ikePayload.(*ike_message.Nonce).NonceData
		}
	}

	ikeSecurityAssociation = &IKESecurityAssociation{
		LocalSPI:           ikeInitiatorSPI,
		RemoteSPI:          ikeMessage.ResponderSPI,
		InitiatorMessageID: 0,
		ResponderMessageID: 0,
		IKESAKey: &ike_security.IKESAKey{
			EncrInfo:  encr.DecodeTransform(proposal.EncryptionAlgorithm[0]),
			IntegInfo: integ.DecodeTransform(proposal.IntegrityAlgorithm[0]),
			PrfInfo:   prf.DecodeTransform(proposal.PseudorandomFunction[0]),
			DhInfo:    dh.DecodeTransform(proposal.DiffieHellmanGroup[0]),
		},
		ConcatenatedNonce:     append(localNonce, remoteNonce...),
		ResponderSignedOctets: append(ikeSecurityAssociation.ResponderSignedOctets, remoteNonce...),
	}

	err = ikeSecurityAssociation.GenerateKeyForIKESA(ikeSecurityAssociation.ConcatenatedNonce,
		sharedKeyExchangeData, ikeSecurityAssociation.LocalSPI, ikeSecurityAssociation.RemoteSPI)
	if err != nil {
		t.Fatalf("Generate key for IKE SA failed: %+v", err)
	}

	n3ue.N3IWFIKESecurityAssociation = ikeSecurityAssociation

	// ============================================
	// IKE_AUTH
	// ============================================
	ikeMessage.Payloads.Reset()
	ikeSecurityAssociation.InitiatorMessageID++

	var ikePayload ike_message.IKEPayloadContainer

	// Identification
	idByte := make([]byte, 8)
	id, err := ike_security.GenerateRandomNumber()
	if err != nil {
		t.Fatal(err)
	}

	binary.BigEndian.PutUint64(idByte, id.Uint64())
	ikePayload.BuildIdentificationInitiator(ike_message.ID_KEY_ID, idByte)

	// Security Association
	securityAssociation = ikePayload.BuildSecurityAssociation()
	// Proposal 1
	inboundSPI, err := generateSPI(n3ue)
	if err != nil {
		t.Fatal(err)
	}
	proposal = securityAssociation.Proposals.BuildProposal(1, ike_message.TypeESP, inboundSPI)
	// ENCR
	proposal.EncryptionAlgorithm.BuildTransform(ike_message.TypeEncryptionAlgorithm, ike_message.ENCR_AES_CBC, &attributeType, &keyLength, nil)
	// INTEG
	proposal.IntegrityAlgorithm.BuildTransform(ike_message.TypeIntegrityAlgorithm, ike_message.AUTH_HMAC_SHA1_96, nil, nil, nil)
	// ESN
	proposal.ExtendedSequenceNumbers.BuildTransform(ike_message.TypeExtendedSequenceNumbers, ike_message.ESN_DISABLE, nil, nil, nil)

	// Traffic Selector
	tsi := ikePayload.BuildTrafficSelectorInitiator()
	tsi.TrafficSelectors.BuildIndividualTrafficSelector(ike_message.TS_IPV4_ADDR_RANGE, 0, 0, 65535, []byte{0, 0, 0, 0}, []byte{255, 255, 255, 255})
	tsr := ikePayload.BuildTrafficSelectorResponder()
	tsr.TrafficSelectors.BuildIndividualTrafficSelector(ike_message.TS_IPV4_ADDR_RANGE, 0, 0, 65535, []byte{0, 0, 0, 0}, []byte{255, 255, 255, 255})

	ikeMessage = ike_message.NewMessage(
		ikeSecurityAssociation.LocalSPI,
		ikeSecurityAssociation.RemoteSPI,
		ike_message.IKE_AUTH, false, true,
		ikeSecurityAssociation.InitiatorMessageID,
		ikePayload,
	)

	// Send to N3IWF
	ikeMessageData, err = ike.EncodeEncrypt(ikeMessage, ikeSecurityAssociation.IKESAKey,
		ike_message.Role_Initiator)
	if err != nil {
		t.Fatalf("EncodeEncrypt IKE message failed: %+v", err)
	}
	if _, err := udpConnection.WriteToUDP(ikeMessageData, n3iwfUDPAddr); err != nil {
		t.Fatalf("Write IKE message failed: %+v", err)
	}

	n3ue.CreateHalfChildSA(ikeSecurityAssociation.InitiatorMessageID,
		binary.BigEndian.Uint32(inboundSPI), -1)

	// Receive N3IWF reply
	n, _, err = udpConnection.ReadFromUDP(buffer)
	if err != nil {
		t.Fatalf("Read IKE message failed: %+v", err)
	}
	ikeMessage.Payloads.Reset()

	ikeMessage, err = ike.DecodeDecrypt(buffer[:n], nil,
		ikeSecurityAssociation.IKESAKey, ike_message.Role_Initiator)
	if err != nil {
		t.Fatalf("Decode IKE meesage: %v", err)
	}

	var eapIdentifier uint8

	for _, ikePayload := range ikeMessage.Payloads {
		switch ikePayload.Type() {
		case ike_message.TypeIDr:
			t.Log("Get IDr")
		case ike_message.TypeAUTH:
			t.Log("Get AUTH")
		case ike_message.TypeCERT:
			t.Log("Get CERT")
		case ike_message.TypeEAP:
			eapIdentifier = ikePayload.(*ike_message.PayloadEap).Identifier
			t.Log("Get EAP")
		}
	}

	// ============================================
	// IKE_AUTH - EAP exchange: EAP-5G start -> Registration Request
	// ============================================
	ikeMessage.Payloads.Reset()
	ikeSecurityAssociation.InitiatorMessageID++

	ikePayload.Reset()

	// EAP-5G vendor type data
	eapVendorTypeData := make([]byte, 2)
	eapVendorTypeData[0] = ike_message.EAP5GType5GNAS

	// AN Parameters
	anParameters := buildEAP5GANParameters()
	anParametersLength := make([]byte, 2)
	binary.BigEndian.PutUint16(anParametersLength, uint16(len(anParameters)))
	eapVendorTypeData = append(eapVendorTypeData, anParametersLength...)
	eapVendorTypeData = append(eapVendorTypeData, anParameters...)

	// NAS
	ueSecurityCapability := ue.GetUESecurityCapability()
	registrationRequest := GetRegistrationRequest(nasIE.RegType_InitialReg,
		mobileIdentity5GS, nil, ueSecurityCapability, nil, nil, nil)

	nasLength := make([]byte, 2)
	binary.BigEndian.PutUint16(nasLength, uint16(len(registrationRequest)))
	eapVendorTypeData = append(eapVendorTypeData, nasLength...)
	eapVendorTypeData = append(eapVendorTypeData, registrationRequest...)

	eapPayload := ikePayload.BuildEAP(eap.EapCodeResponse, eapIdentifier)
	eapPayload.EapTypeData = ike_message.BuildEapExpanded(eap.VendorId3GPP, eap.VendorTypeEAP5G, eapVendorTypeData)

	ikeMessage = ike_message.NewMessage(
		ikeSecurityAssociation.LocalSPI,
		ikeSecurityAssociation.RemoteSPI,
		ike_message.IKE_AUTH,
		false, true,
		ikeSecurityAssociation.InitiatorMessageID,
		ikePayload,
	)

	// Send to N3IWF
	ikeMessageData, err = ike.EncodeEncrypt(ikeMessage, ikeSecurityAssociation.IKESAKey,
		ike_message.Role_Initiator)
	if err != nil {
		t.Fatalf("EncodeEncrypt IKE message failed: %+v", err)
	}
	if _, err := udpConnection.WriteToUDP(ikeMessageData, n3iwfUDPAddr); err != nil {
		t.Fatalf("Write IKE message failed: %+v", err)
	}

	// Receive N3IWF reply
	n, _, err = udpConnection.ReadFromUDP(buffer)
	if err != nil {
		t.Fatalf("Read IKE message failed: %+v", err)
	}

	ikeMessage.Payloads.Reset()

	ikeMessage, err = ike.DecodeDecrypt(buffer[:n], nil,
		ikeSecurityAssociation.IKESAKey, ike_message.Role_Initiator)
	if err != nil {
		t.Fatalf("Decode IKE meesage: %v", err)
	}

	var eapReq *ike_message.PayloadEap
	var eapExpanded *eap.EapExpanded

	eapReq, ok = ikeMessage.Payloads[0].(*ike_message.PayloadEap)
	if !ok {
		t.Fatalf("Received packet is not an EAP payload")
	}

	eapExpanded, ok = eapReq.EapTypeData.(*eap.EapExpanded)
	if !ok {
		t.Fatalf("The EAP data is not an EAP expended.")
	}

	// Decode NAS - Authentication Request
	nasData := eapExpanded.VendorData[4:]
	decodedNAS, err := nasMessage.ParseGMM(nasData)
	if err != nil {
		t.Fatalf("Decode plain NAS fail: %+v", err)
	}

	// Calculate for RES*
	assert.NotNil(t, decodedNAS)
	rand := decodedNAS.(*nasMessage.AuthReq).AuthParamRAND5GAuthChlg.Rand
	resStat := ue.DeriveRESstarAndSetKey(ue.AuthenticationSubs, rand[:], "5G:mnc093.mcc208.3gppnetwork.org")

	// send NAS Authentication Response
	pdu := GetAuthenticationResponse(resStat, "")

	// ============================================
	// IKE_AUTH - EAP exchange: Authentication Response
	// ============================================
	ikeMessage.Payloads.Reset()
	ikeSecurityAssociation.InitiatorMessageID++

	ikePayload.Reset()

	eapVendorTypeData = make([]byte, 4)
	eapVendorTypeData[0] = ike_message.EAP5GType5GNAS

	nasLength = make([]byte, 2)
	binary.BigEndian.PutUint16(nasLength, uint16(len(pdu)))
	eapVendorTypeData = append(eapVendorTypeData, nasLength...)
	eapVendorTypeData = append(eapVendorTypeData, pdu...)

	eapPayload = ikePayload.BuildEAP(eap.EapCodeResponse, eapReq.Identifier)
	eapPayload.EapTypeData = ike_message.BuildEapExpanded(eap.VendorId3GPP, eap.VendorTypeEAP5G, eapVendorTypeData)

	ikeMessage = ike_message.NewMessage(
		ikeSecurityAssociation.LocalSPI,
		ikeSecurityAssociation.RemoteSPI,
		ike_message.IKE_AUTH,
		false, true,
		ikeSecurityAssociation.InitiatorMessageID,
		ikePayload,
	)
	// Send to N3IWF
	ikeMessageData, err = ike.EncodeEncrypt(ikeMessage, ikeSecurityAssociation.IKESAKey,
		ike_message.Role_Initiator)
	if err != nil {
		t.Fatalf("EncodeEncrypt IKE message failed: %+v", err)
	}
	_, err = udpConnection.WriteToUDP(ikeMessageData, n3iwfUDPAddr)
	if err != nil {
		t.Fatalf("Write IKE message failed: %+v", err)
	}

	// Receive N3IWF reply
	n, _, err = udpConnection.ReadFromUDP(buffer)
	if err != nil {
		t.Fatalf("Read IKE Message fail: %+v", err)
	}
	ikeMessage.Payloads.Reset()
	ikeMessage, err = ike.DecodeDecrypt(buffer[:n], nil,
		ikeSecurityAssociation.IKESAKey, ike_message.Role_Initiator)
	if err != nil {
		t.Fatalf("Decode IKE meesage: %v", err)
	}

	eapReq, ok = ikeMessage.Payloads[0].(*ike_message.PayloadEap)
	if !ok {
		t.Fatal("Received packet is not an EAP payload")
		return
	}
	eapExpanded, ok = eapReq.EapTypeData.(*eap.EapExpanded)
	if !ok {
		t.Fatal("Received packet is not an EAP expended payload")
		return
	}

	// send NAS Security Mode Complete Msg
	registrationRequestWith5GMM := GetRegistrationRequest(nasIE.RegType_InitialReg,
		mobileIdentity5GS, nil, ueSecurityCapability, ue.Get5GMMCapability(), nil, nil)
	pdu = GetSecurityModeComplete(registrationRequestWith5GMM)
	pdu, err = EncodeNasPduWithSecurity(ue, pdu, nasMessage.SecHdrTypeIntegrityProtectedAndCipheredWithNew5gNasSecCtx, true, true)
	assert.Nil(t, err)

	// ============================================
	// IKE_AUTH - EAP exchange: Security Mode Complete
	// ============================================
	ikeMessage.Payloads.Reset()
	ikeSecurityAssociation.InitiatorMessageID++

	ikePayload.Reset()

	eapVendorTypeData = make([]byte, 4)
	eapVendorTypeData[0] = ike_message.EAP5GType5GNAS

	nasLength = make([]byte, 2)
	binary.BigEndian.PutUint16(nasLength, uint16(len(pdu)))
	eapVendorTypeData = append(eapVendorTypeData, nasLength...)
	eapVendorTypeData = append(eapVendorTypeData, pdu...)

	eapPayload = ikePayload.BuildEAP(eap.EapCodeResponse, eapReq.Identifier)
	eapPayload.EapTypeData = ike_message.BuildEapExpanded(eap.VendorId3GPP, eap.VendorTypeEAP5G, eapVendorTypeData)

	ikeMessage = ike_message.NewMessage(
		ikeSecurityAssociation.LocalSPI,
		ikeSecurityAssociation.RemoteSPI,
		ike_message.IKE_AUTH,
		false, true,
		ikeSecurityAssociation.InitiatorMessageID,
		ikePayload,
	)

	// Send to N3IWF
	ikeMessageData, err = ike.EncodeEncrypt(ikeMessage, ikeSecurityAssociation.IKESAKey,
		ike_message.Role_Initiator)
	if err != nil {
		t.Fatalf("EncodeEncrypt IKE message failed: %+v", err)
	}
	_, err = udpConnection.WriteToUDP(ikeMessageData, n3iwfUDPAddr)
	if err != nil {
		t.Fatalf("Write IKE message failed: %+v", err)
	}

	// Receive N3IWF reply
	n, _, err = udpConnection.ReadFromUDP(buffer)
	if err != nil {
		t.Fatalf("Read IKE Message fail: %+v", err)
		return
	}
	ikeMessage.Payloads.Reset()

	ikeMessage, err = ike.DecodeDecrypt(buffer[:n], nil,
		ikeSecurityAssociation.IKESAKey, ike_message.Role_Initiator)
	if err != nil {
		t.Fatalf("Decode IKE meesage: %v", err)
	}

	eapReq, ok = ikeMessage.Payloads[0].(*ike_message.PayloadEap)
	if !ok {
		t.Fatal("Received packet is not an EAP payload")
	}
	if eapReq.Code != eap.EapCodeSuccess {
		t.Fatal("Not Success")
	}

	// ============================================
	// IKE_AUTH - Authentication (derive Kn3iwf, send AUTH + Configuration Request)
	// ============================================
	ikeMessage.Payloads.Reset()
	ikeSecurityAssociation.InitiatorMessageID++

	ikePayload.Reset()

	Kn3iwf, err := deriveKn3iwf(ue)
	if err != nil {
		t.Fatalf("Get Kn3iwf error : %+v", err)
	}

	var idPayload ike_message.IKEPayloadContainer
	idPayload.BuildIdentificationInitiator(ike_message.ID_KEY_ID, idByte)
	idPayloadData, err := idPayload.Encode()
	if err != nil {
		t.Fatalf("Encode IKE payload failed : %+v", err)
	}
	if _, err = ikeSecurityAssociation.Prf_i.Write(idPayloadData[4:]); err != nil {
		t.Fatalf("Pseudorandom function write error: %+v", err)
	}
	ikeSecurityAssociation.ResponderSignedOctets = append(
		ikeSecurityAssociation.ResponderSignedOctets,
		ikeSecurityAssociation.Prf_i.Sum(nil)...)

	pseudorandomFunction := ikeSecurityAssociation.PrfInfo.Init(Kn3iwf)
	if _, err = pseudorandomFunction.Write([]byte("Key Pad for IKEv2")); err != nil {
		t.Fatalf("Pseudorandom function write error: %+v", err)
	}
	secret := pseudorandomFunction.Sum(nil)
	pseudorandomFunction = ikeSecurityAssociation.PrfInfo.Init(secret)
	pseudorandomFunction.Reset()
	if _, err = pseudorandomFunction.Write(ikeSecurityAssociation.ResponderSignedOctets); err != nil {
		t.Fatalf("Pseudorandom function write error: %+v", err)
	}

	ikePayload.BuildAuthentication(ike_message.SharedKeyMesageIntegrityCode, pseudorandomFunction.Sum(nil))

	// Configuration Request
	configurationRequest := ikePayload.BuildConfiguration(ike_message.CFG_REQUEST)
	configurationRequest.ConfigurationAttribute.BuildConfigurationAttribute(ike_message.INTERNAL_IP4_ADDRESS, nil)

	ikeMessage = ike_message.NewMessage(
		ikeSecurityAssociation.LocalSPI,
		ikeSecurityAssociation.RemoteSPI,
		ike_message.IKE_AUTH,
		false, true,
		ikeSecurityAssociation.InitiatorMessageID,
		ikePayload,
	)

	ikeMessageData, err = ike.EncodeEncrypt(ikeMessage, ikeSecurityAssociation.IKESAKey,
		ike_message.Role_Initiator)
	if err != nil {
		t.Fatalf("EncodeEncrypt IKE message failed: %+v", err)
	}
	_, err = udpConnection.WriteToUDP(ikeMessageData, n3iwfUDPAddr)
	if err != nil {
		t.Fatalf("Write IKE message failed: %+v", err)
	}

	// Receive N3IWF reply
	n, _, err = udpConnection.ReadFromUDP(buffer)
	if err != nil {
		t.Fatalf("Read IKE Message fail: %+v", err)
	}

	ikeMessage, err = ike.DecodeDecrypt(buffer[:n], nil,
		ikeSecurityAssociation.IKESAKey, ike_message.Role_Initiator)
	if err != nil {
		t.Fatalf("Decode IKE meesage: %v", err)
	}

	// AUTH, SAr2, TSi, Tsr, N(NAS_IP_ADDRESS), N(NAS_TCP_PORT)
	var responseSecurityAssociation *ike_message.SecurityAssociation
	var responseTrafficSelectorInitiator *ike_message.TrafficSelectorInitiator
	var responseTrafficSelectorResponder *ike_message.TrafficSelectorResponder
	var responseConfiguration *ike_message.Configuration
	n3iwfNASAddr := new(net.TCPAddr)

	for _, ikePayload := range ikeMessage.Payloads {
		switch ikePayload.Type() {
		case ike_message.TypeAUTH:
			t.Log("Get Authentication from N3IWF")
		case ike_message.TypeSA:
			responseSecurityAssociation = ikePayload.(*ike_message.SecurityAssociation)
			ikeSecurityAssociation.IKEAuthResponseSA = responseSecurityAssociation
		case ike_message.TypeTSi:
			responseTrafficSelectorInitiator = ikePayload.(*ike_message.TrafficSelectorInitiator)
		case ike_message.TypeTSr:
			responseTrafficSelectorResponder = ikePayload.(*ike_message.TrafficSelectorResponder)
		case ike_message.TypeN:
			notification := ikePayload.(*ike_message.Notification)
			if notification.NotifyMessageType == ike_message.Vendor3GPPNotifyTypeNAS_IP4_ADDRESS {
				n3iwfNASAddr.IP = net.IPv4(notification.NotificationData[0], notification.NotificationData[1], notification.NotificationData[2], notification.NotificationData[3])
			}
			if notification.NotifyMessageType == ike_message.Vendor3GPPNotifyTypeNAS_TCP_PORT {
				n3iwfNASAddr.Port = int(binary.BigEndian.Uint16(notification.NotificationData))
			}
		case ike_message.TypeCP:
			responseConfiguration = ikePayload.(*ike_message.Configuration)
			if responseConfiguration.ConfigurationType == ike_message.CFG_REPLY {
				for _, configAttr := range responseConfiguration.ConfigurationAttribute {
					if configAttr.Type == ike_message.INTERNAL_IP4_ADDRESS {
						ueInnerAddr.IP = configAttr.Value
					}
					if configAttr.Type == ike_message.INTERNAL_IP4_NETMASK {
						ueInnerAddr.Mask = configAttr.Value
					}
				}
			}
		}
	}

	OutboundSPI := binary.BigEndian.Uint32(ikeSecurityAssociation.IKEAuthResponseSA.Proposals[0].SPI)
	childSecurityAssociationContext, err := n3ue.CompleteChildSA(
		0x01, OutboundSPI, ikeSecurityAssociation.IKEAuthResponseSA)
	if err != nil {
		t.Fatalf("Create child security association context failed: %+v", err)
	}
	err = parseIPAddressInformationToChildSecurityAssociation(childSecurityAssociationContext,
		responseTrafficSelectorInitiator.TrafficSelectors[0],
		responseTrafficSelectorResponder.TrafficSelectors[0])
	if err != nil {
		t.Fatalf("Parse IP address to child security association failed: %+v", err)
	}
	// Select TCP traffic
	childSecurityAssociationContext.SelectedIPProtocol = unix.IPPROTO_TCP

	if err := childSecurityAssociationContext.GenerateKeyForChildSA(ikeSecurityAssociation.IKESAKey,
		ikeSecurityAssociation.ConcatenatedNonce); err != nil {
		t.Fatalf("Generate key for child SA failed: %+v", err)
	}

	var linkIPSec netlink.Link

	// Setup interface for ipsec
	newXfrmiName := fmt.Sprintf("%s-default", n3ueInfo_XfrmiName)
	if linkIPSec, err = setupIPsecXfrmi(newXfrmiName, n3ueInfo_IPSecIfaceName, n3ueInfo_XfrmiId, ueInnerAddr); err != nil {
		t.Fatalf("Setup XFRM interface %s fail: %+v", newXfrmiName, err)
	}

	defer func() {
		if err := netlink.LinkDel(linkIPSec); err != nil {
			t.Fatalf("Delete XFRM interface %s fail: %+v", newXfrmiName, err)
		} else {
			t.Logf("Delete XFRM interface: %s", newXfrmiName)
		}
	}()

	// Apply XFRM rules
	if err = applyXFRMRule(true, n3ueInfo_XfrmiId, childSecurityAssociationContext); err != nil {
		t.Fatalf("Applying XFRM rules failed: %+v", err)
	}

	defer func() {
		_ = netlink.XfrmPolicyFlush()
		_ = netlink.XfrmStateFlush(netlink.XFRM_PROTO_IPSEC_ANY)
	}()

	localTCPAddr := &net.TCPAddr{
		IP: ueInnerAddr.IP,
	}
	tcpConnWithN3IWF, err := net.DialTCP("tcp", localTCPAddr, n3iwfNASAddr)
	if err != nil {
		t.Fatal(err)
	}

	nasEnv := make([]byte, 65535)

	n, err = tcpConnWithN3IWF.Read(nasEnv)
	if err != nil {
		t.Fatal(err)
		return
	}

	nasEnv, n, err = DecapNasPduFromEnvelope(nasEnv[:n])
	if err != nil {
		t.Fatal(err)
	}
	nasMsg, err := NASDecode(ue, nasMessage.SecHdrTypeIntegrityProtectedAndCiphered, nasEnv[:n])
	if err != nil {
		t.Fatalf("NAS Decode Fail: %+v", err)
	}

	spew.Config.Indent = "\t"
	nasStr := spew.Sdump(nasMsg)
	t.Logf("Get NAS Security Mode Command Message:\n %+v", nasStr)

	// send NAS Registration Complete Msg
	pdu = GetRegistrationComplete(nil)
	pdu, err = EncodeNasPduInEnvelopeWithSecurity(ue, pdu, nasMessage.SecHdrTypeIntegrityProtectedAndCiphered, true, false)
	if err != nil {
		t.Fatal(err)
		return
	}
	_, err = tcpConnWithN3IWF.Write(pdu)
	if err != nil {
		t.Fatal(err)
		return
	}

	time.Sleep(500 * time.Millisecond)

	// ============================================
	// UE requests the first PDU session setup
	// ============================================
	sNssai := models.Snssai{
		Sst: SST,
		Sd:  SD,
	}

	var pduSessionId uint8 = 1

	pdu = GetUlNasTransport_PduSessionEstablishmentRequest(pduSessionId, nasIE.ReqType_InitialReq, "internet", &sNssai)
	pdu, err = EncodeNasPduInEnvelopeWithSecurity(ue, pdu, nasMessage.SecHdrTypeIntegrityProtectedAndCiphered, true, false)
	if err != nil {
		t.Fatal(err)
		return
	}
	_, err = tcpConnWithN3IWF.Write(pdu)
	if err != nil {
		t.Fatal(err)
		return
	}

	// Receive N3IWF reply
	n, _, err = udpConnection.ReadFromUDP(buffer)
	if err != nil {
		t.Fatalf("Read IKE Message fail: %+v", err)
	}
	ikeMessage.Payloads.Reset()
	ikeMessage, err = ike.DecodeDecrypt(buffer[:n], nil,
		ikeSecurityAssociation.IKESAKey, ike_message.Role_Initiator)
	if err != nil {
		t.Fatalf("Decode IKE meesage: %v", err)
	}

	var QoSInfo *PDUQoSInfo

	var upIPAddr net.IP
	for _, ikePayload := range ikeMessage.Payloads {
		switch ikePayload.Type() {
		case ike_message.TypeSA:
			responseSecurityAssociation = ikePayload.(*ike_message.SecurityAssociation)
			OutboundSPI = binary.BigEndian.Uint32(responseSecurityAssociation.Proposals[0].SPI)
		case ike_message.TypeTSi:
			responseTrafficSelectorInitiator = ikePayload.(*ike_message.TrafficSelectorInitiator)
		case ike_message.TypeTSr:
			responseTrafficSelectorResponder = ikePayload.(*ike_message.TrafficSelectorResponder)
		case ike_message.TypeN:
			notification := ikePayload.(*ike_message.Notification)
			if notification.NotifyMessageType == ike_message.Vendor3GPPNotifyType5G_QOS_INFO {
				t.Log("Received Qos Flow settings")
				if info, err := parse5GQoSInfoNotify(notification); err == nil {
					QoSInfo = info
					t.Logf("NotificationData:%+v", notification.NotificationData)
					if QoSInfo.isDSCPSpecified {
						t.Logf("DSCP is specified but test not support")
					}
				} else {
					t.Logf("%+v", err)
				}
			}
			if notification.NotifyMessageType == ike_message.Vendor3GPPNotifyTypeUP_IP4_ADDRESS {
				upIPAddr = notification.NotificationData[:4]
				t.Logf("UP IP Address: %+v\n", upIPAddr)
			}
		case ike_message.TypeNiNr:
			responseNonce := ikePayload.(*ike_message.Nonce)
			ikeSecurityAssociation.ConcatenatedNonce = responseNonce.NonceData
		}
	}

	// IKE CREATE_CHILD_SA response
	ikeMessage.Payloads.Reset()
	ikeSecurityAssociation.ResponderMessageID = ikeMessage.MessageID

	ikePayload.Reset()

	// SA
	inboundSPI, err = generateSPI(n3ue)
	if err != nil {
		t.Fatal(err)
	}
	responseSecurityAssociation.Proposals[0].SPI = inboundSPI
	ikePayload = append(ikePayload, responseSecurityAssociation)

	// TSi
	ikePayload = append(ikePayload, responseTrafficSelectorInitiator)

	// TSr
	ikePayload = append(ikePayload, responseTrafficSelectorResponder)

	// Nonce
	localNonceBigInt, err = ike_security.GenerateRandomNumber()
	if err != nil {
		t.Fatalf("Generate local nonce: %v", err)
	}
	localNonce = localNonceBigInt.Bytes()
	ikeSecurityAssociation.ConcatenatedNonce = append(ikeSecurityAssociation.ConcatenatedNonce, localNonce...)
	ikePayload.BuildNonce(localNonce)

	ikeMessage = ike_message.NewMessage(
		ikeSecurityAssociation.LocalSPI,
		ikeSecurityAssociation.RemoteSPI,
		ike_message.CREATE_CHILD_SA,
		true, true,
		ikeSecurityAssociation.ResponderMessageID,
		ikePayload,
	)

	ikeMessageData, err = ike.EncodeEncrypt(ikeMessage, ikeSecurityAssociation.IKESAKey,
		ike_message.Role_Initiator)
	if err != nil {
		t.Fatalf("EncodeEncrypt IKE message failed: %+v", err)
	}
	_, err = udpConnection.WriteToUDP(ikeMessageData, n3iwfUDPAddr)
	if err != nil {
		t.Fatalf("Write IKE message failed: %+v", err)
	}

	n3ue.CreateHalfChildSA(ikeSecurityAssociation.ResponderMessageID,
		binary.BigEndian.Uint32(inboundSPI), -1)
	childSecurityAssociationContextUserPlane, err := n3ue.CompleteChildSA(
		ikeSecurityAssociation.ResponderMessageID, OutboundSPI, responseSecurityAssociation)
	if err != nil {
		t.Fatalf("Create child security association context failed: %+v", err)
	}
	err = parseIPAddressInformationToChildSecurityAssociation(childSecurityAssociationContextUserPlane, responseTrafficSelectorResponder.TrafficSelectors[0], responseTrafficSelectorInitiator.TrafficSelectors[0])
	if err != nil {
		t.Fatalf("Parse IP address to child security association failed: %+v", err)
	}
	// Select GRE traffic
	childSecurityAssociationContextUserPlane.SelectedIPProtocol = unix.IPPROTO_GRE

	if err := childSecurityAssociationContextUserPlane.GenerateKeyForChildSA(ikeSecurityAssociation.IKESAKey,
		ikeSecurityAssociation.ConcatenatedNonce); err != nil {
		t.Fatalf("Generate key for child SA failed: %+v", err)
	}

	// Apply XFRM rules
	if err = applyXFRMRule(false, n3ueInfo_XfrmiId, childSecurityAssociationContextUserPlane); err != nil {
		t.Fatalf("Applying XFRM rules failed: %+v", err)
	}

	// Reference test's own TODO: UE Configuration Update Command content isn't checked.
	if n, err := tcpConnWithN3IWF.Read(buffer); err != nil {
		t.Fatalf("No UeConfigUpdate Message: %+v", err)
	} else {
		_ = n
	}

	var pduAddress net.IP

	// Read NAS from N3IWF
	if n, err := tcpConnWithN3IWF.Read(buffer); err != nil {
		t.Fatalf("Read NAS Message Fail:%+v", err)
	} else {
		nasMsg, err := DecodePDUSessionEstablishmentAccept(ue, n, buffer)
		if err != nil {
			t.Fatalf("DecodePDUSessionEstablishmentAccept Fail: %+v", err)
		}

		spew.Config.Indent = "\t"
		nasStr := spew.Sdump(nasMsg)
		t.Log("Dump DecodePDUSessionEstablishmentAccept:\n", nasStr)
		pduAddress, err = GetPDUAddress(nasMsg)
		if err != nil {
			t.Fatalf("GetPDUAddress Fail: %+v", err)
		}

		t.Logf("PDU Address: %s", pduAddress.String())
	}

	var linkGRE netlink.Link

	newGREName := fmt.Sprintf("%s-id-%d", n3ueInfo_GreIfaceName, n3ueInfo_XfrmiId)

	if linkGRE, err = setupGreTunnel(newGREName, newXfrmiName, ueInnerAddr.IP, upIPAddr, pduAddress, QoSInfo, t); err != nil {
		t.Fatalf("Setup GRE tunnel %s Fail %+v", newGREName, err)
	}

	defer func() {
		_ = netlink.LinkDel(linkGRE)
		t.Logf("Delete interface: %s", linkGRE.Attrs().Name)
	}()

	// Add a host route for the ping test's target (EIGHT_IP, see below) via the GRE
	// tunnel. The reference test adds a full 0.0.0.0/0 default route instead, but this
	// container already has a default route via the docker bridge (same metric), so a
	// second 0.0.0.0/0 route collides with EEXIST — N3IWF's own log shows the same
	// "netlink.RouteAdd: file exists" warning on startup for the same reason, and it
	// just logs and continues since it doesn't need that route for its own operation.
	// A /32 host route wins on longest-prefix-match over the existing default route
	// without colliding with it, so ping traffic actually goes through the tunnel
	// while everything else in this container (e.g. webconsole API calls) is unaffected.
	pingTarget := net.ParseIP(EIGHT_IP)
	upRoute := &netlink.Route{
		LinkIndex: linkGRE.Attrs().Index,
		Dst: &net.IPNet{
			IP:   pingTarget,
			Mask: net.CIDRMask(32, 32),
		},
	}
	if err := netlink.RouteAdd(upRoute); err != nil {
		t.Fatal(err)
	}

	// ============================================
	// Request 3 more PDU sessions over the existing IKE/NAS-TCP connection
	// ============================================
	for i := 1; i <= 3; i++ {
		var (
			ifaces []netlink.Link
			err    error
		)
		t.Logf("%d times PDU Session Est Request Start", i+1)
		if ifaces, err = sendPduSessionEstablishmentRequest(pduSessionId+uint8(i), ue, n3ue, ikeSecurityAssociation, udpConnection, tcpConnWithN3IWF, t); err != nil {
			t.Fatalf("Session Est Request Fail: %+v", err)
		} else {
			t.Logf("Create %d interfaces", len(ifaces))
		}

		defer func() {
			for _, iface := range ifaces {
				if err := netlink.LinkDel(iface); err != nil {
					t.Fatalf("Delete interface %s fail: %+v", iface.Attrs().Name, err)
				} else {
					t.Logf("Delete interface: %s", iface.Attrs().Name)
				}
			}
		}()
	}

	// ============================================
	// Verify user-plane connectivity with a real ping through the GRE/IPsec tunnel.
	// The reference test pings 10.60.0.101, an address within the UPF's DNN pool
	// (10.60.0.0/16) that nothing actually listens on in this environment — confirmed
	// by a live run: it routed correctly through the tunnel but got 100% packet loss
	// since there was no host there to reply. Ping EIGHT_IP instead (the real, already
	// verified-reachable external address TestDC/TestDynamicDC/TestXnDCHandover use),
	// to prove the non-3GPP PDU session actually delivers traffic end-to-end. Source is
	// the first PDU session's actual allocated address (session 1, logged above as
	// "PDU Address: 10.60.0.1" — confirmed correct in a live run, not a guess).
	// ============================================
	pinger, err := ping.NewPinger(EIGHT_IP)
	if err != nil {
		t.Fatal(err)
		return
	}

	// Run with root
	pinger.SetPrivileged(true)

	pinger.OnRecv = func(pkt *ping.Packet) {
		t.Logf("%d bytes from %s: icmp_seq=%d time=%v\n",
			pkt.Nbytes, pkt.IPAddr, pkt.Seq, pkt.Rtt)
	}
	pinger.OnFinish = func(stats *ping.Statistics) {
		t.Logf("\n--- %s ping statistics ---\n", stats.Addr)
		t.Logf("%d packets transmitted, %d packets received, %v%% packet loss\n",
			stats.PacketsSent, stats.PacketsRecv, stats.PacketLoss)
		t.Logf("round-trip min/avg/max/stddev = %v/%v/%v/%v\n",
			stats.MinRtt, stats.AvgRtt, stats.MaxRtt, stats.StdDevRtt)
	}

	pinger.Count = 5
	pinger.Timeout = 10 * time.Second
	pinger.Source = "10.60.0.1"

	time.Sleep(3 * time.Second)

	pinger.Run()

	time.Sleep(1 * time.Second)

	stats := pinger.Statistics()
	if stats.PacketsSent != stats.PacketsRecv {
		t.Fatal("Ping Failed")
		return
	}
}
