package test

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
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

	ike_message "github.com/free5gc/ike/message"
	ike_security "github.com/free5gc/ike/security"
	"github.com/free5gc/ike/security/dh"
	"github.com/free5gc/ike/security/integ"
	"github.com/free5gc/ike/security/prf"

	nasIE "github.com/free5gc/nas/ie"
	nasMessage "github.com/free5gc/nas/message"
	"github.com/free5gc/openapi/models"
)

// tngfFixedRadiusAuthenticator is the Request Authenticator the reference test reuses
// (unchanged) for every RADIUS Access-Request after the very first one, instead of a
// fresh random value per RFC 2865. This looks non-compliant, but it's what the
// reference test does and TNGF accepts it in practice, so it's ported faithfully rather
// than "fixed".
const tngfFixedRadiusAuthenticator = "ea408c3a615fc82899bb8f2fa2e374e9"

// TestTngf simulates a full trusted-non-3GPP-access UE talking to TNGF: EAP-5G relayed
// over RADIUS Access-Request/Access-Accept cycles (Identity, Registration Request,
// Authentication Response, Security Mode Complete, 5G-Notification) to completion
// *before* any IKE exchange starts, then IKE_SA_INIT/IKE_AUTH (ENCR_NULL, integrity-only
// — see tngf.go), IPsec child SA + XFRM interface setup, NAS Registration Complete and
// PDU Session Establishment over the resulting NAS-over-TCP connection, a GRE tunnel for
// the PDU session's user-plane traffic, and a real ping to verify end-to-end delivery.
//
// Unlike N3IWF, TNGF's own reference test only establishes a single PDU session.
func TestTngf(t *testing.T) {
	// New UE
	ue := NewRanUeContext(UE_IMSI, 1, nasMessage.AlgCiphering128NEA0, nasMessage.AlgIntegrity128NIA2,
		models.AccessType_NON_3_GPP_ACCESS)
	ue.AmfUeNgapId = 1
	ue.AuthenticationSubs = GetAuthSubscription(UE_K, UE_OPC, "")
	// mobileIdentityBuffer is kept as a plain byte slice (rather than only living inside
	// mobileIdentity5GS) because buildEAP5GANParametersTNGF and the IKE Identification
	// payload both need the identity's raw IEI+content bytes, which ie.MobileId5GS no
	// longer exposes directly (see tngf.go's buildEAP5GANParametersTNGF doc comment).
	mobileIdentityBuffer := []uint8{0x01, 0x02, 0xf8, 0x39, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10}
	mobileIdentity5GS := MobileIdentity5GS(mobileIdentityBuffer)

	// Used to save IPsec/IKE related data
	tngfue := new(TNGFUe)
	tngfue.TNGFChildSecurityAssociation = make(map[uint32]*TNGFChildSecurityAssociation)
	tngfue.TemporaryExchangeMsgIDChildSAMapping = make(map[uint32]*TNGFChildSecurityAssociation)

	tngfRadiusUDPAddr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", TNGF_IP, TNGF_RADIUS_PORT))
	if err != nil {
		t.Fatalf("Resolve UDP address fail: %+v", err)
	}
	tngfUDPAddr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", TNGF_IP, TNGF_IKE_PORT))
	if err != nil {
		t.Fatalf("Resolve UDP address fail: %+v", err)
	}

	udpConnection, err := setupUDPSocket()
	if err != nil {
		t.Fatalf("Setup UDP socket fail: %+v", err)
	}
	radiusConnection, err := setupRadiusSocket()
	if err != nil {
		t.Fatalf("Setup Radius socket fail: %+v", err)
	}

	buffer := make([]byte, 65535)

	// ============================================
	// RADIUS: EAP-Response/Identity
	// ============================================
	radiusAuthenticator := make([]byte, 16)
	if _, err := rand.Read(radiusAuthenticator); err != nil {
		t.Fatalf("Generate radius authenticator fail: %+v", err)
	}

	identifier, err := ike_security.GenerateRandomUint8()
	if err != nil {
		t.Fatalf("Random number failed: %+v", err)
	}
	eapPayload, err := marshalEAPIdentity(identifier, []byte("tngfue"))
	if err != nil {
		t.Fatalf("Marshal EAP identity fail: %+v", err)
	}
	radiusMsg, err := buildTngfAccessRequest(0x05, radiusAuthenticator, eapPayload)
	if err != nil {
		t.Fatalf("Build RADIUS Access-Request fail: %+v", err)
	}
	pkt, err := radiusMsg.Encode()
	if err != nil {
		t.Fatalf("Radius message encode fail: %+v", err)
	}
	if _, err := radiusConnection.WriteToUDP(pkt, tngfRadiusUDPAddr); err != nil {
		t.Fatalf("Write Radius message fail: %+v", err)
	}

	if _, _, err := radiusConnection.ReadFromUDP(buffer); err != nil {
		t.Fatalf("Read Radius message failed: %+v", err)
	}

	fixedAuthenticator, err := hex.DecodeString(tngfFixedRadiusAuthenticator)
	if err != nil {
		t.Fatalf("Decode fixed radius authenticator fail: %+v", err)
	}

	// ============================================
	// RADIUS: EAP-Response/5G-NAS carrying AN-Parameters + Registration Request
	// ============================================
	identifier, err = ike_security.GenerateRandomUint8()
	if err != nil {
		t.Fatalf("Random number failed: %+v", err)
	}
	anParameters := buildEAP5GANParametersTNGF(0, mobileIdentityBuffer)
	anParametersLength := make([]byte, 2)
	binary.BigEndian.PutUint16(anParametersLength, uint16(len(anParameters)))

	ueSecurityCapability := ue.GetUESecurityCapability()
	registrationRequest := GetRegistrationRequest(nasIE.RegType_InitialReg,
		mobileIdentity5GS, nil, ueSecurityCapability, nil, nil, nil)

	eapVendorTypeData := make([]byte, 2)
	eapVendorTypeData[0] = ike_message.EAP5GType5GNAS
	eapVendorTypeData = append(eapVendorTypeData, anParametersLength...)
	eapVendorTypeData = append(eapVendorTypeData, anParameters...)
	nasLength := make([]byte, 2)
	binary.BigEndian.PutUint16(nasLength, uint16(len(registrationRequest)))
	eapVendorTypeData = append(eapVendorTypeData, nasLength...)
	eapVendorTypeData = append(eapVendorTypeData, registrationRequest...)

	eapPayload, err = marshalEAP5GNAS(identifier, eapVendorTypeData)
	if err != nil {
		t.Fatalf("Marshal EAP-5G-NAS fail: %+v", err)
	}
	radiusMsg, err = buildTngfAccessRequest(0x06, fixedAuthenticator, eapPayload)
	if err != nil {
		t.Fatalf("Build RADIUS Access-Request fail: %+v", err)
	}
	pkt, err = radiusMsg.Encode()
	if err != nil {
		t.Fatalf("Radius message encode fail: %+v", err)
	}
	if _, err := radiusConnection.WriteToUDP(pkt, tngfRadiusUDPAddr); err != nil {
		t.Fatalf("Write Radius message fail: %+v", err)
	}

	n, _, err := radiusConnection.ReadFromUDP(buffer)
	if err != nil {
		t.Fatalf("Read Radius message failed: %+v", err)
	}
	respRadiusMsg := new(RadiusMessage)
	if err := respRadiusMsg.Decode(buffer[:n]); err != nil {
		t.Fatalf("Decode Radius message failed: %+v", err)
	}
	eapExpanded, err := decodeEAPExpanded(respRadiusMsg.getEAPMessage())
	if err != nil {
		t.Fatalf("Decode EAP-5G-NAS fail: %+v", err)
	}

	// Decode NAS - Authentication Request
	nasData := eapExpanded.VendorData[4:]
	decodedNAS, err := nasMessage.ParseGMM(nasData)
	if err != nil {
		t.Fatalf("Decode plain NAS fail: %+v", err)
	}

	// Calculate for RES*
	assert.NotNil(t, decodedNAS)
	randValue := decodedNAS.(*nasMessage.AuthReq).AuthParamRAND5GAuthChlg.Rand
	resStat := ue.DeriveRESstarAndSetKey(ue.AuthenticationSubs, randValue[:], "5G:mnc093.mcc208.3gppnetwork.org")

	// ============================================
	// RADIUS: EAP-Response/5G-NAS carrying Authentication Response
	// ============================================
	identifier, err = ike_security.GenerateRandomUint8()
	if err != nil {
		t.Fatalf("Random number failed: %+v", err)
	}
	authenticationResponse := GetAuthenticationResponse(resStat, "")

	eapVendorTypeData = make([]byte, 2)
	eapVendorTypeData[0] = ike_message.EAP5GType5GNAS
	eapVendorTypeData = append(eapVendorTypeData, anParametersLength...)
	eapVendorTypeData = append(eapVendorTypeData, anParameters...)
	nasLength = make([]byte, 2)
	binary.BigEndian.PutUint16(nasLength, uint16(len(authenticationResponse)))
	eapVendorTypeData = append(eapVendorTypeData, nasLength...)
	eapVendorTypeData = append(eapVendorTypeData, authenticationResponse...)

	eapPayload, err = marshalEAP5GNAS(identifier, eapVendorTypeData)
	if err != nil {
		t.Fatalf("Marshal EAP-5G-NAS fail: %+v", err)
	}
	radiusMsg, err = buildTngfAccessRequest(0x07, fixedAuthenticator, eapPayload)
	if err != nil {
		t.Fatalf("Build RADIUS Access-Request fail: %+v", err)
	}
	pkt, err = radiusMsg.Encode()
	if err != nil {
		t.Fatalf("Radius message encode fail: %+v", err)
	}
	if _, err := radiusConnection.WriteToUDP(pkt, tngfRadiusUDPAddr); err != nil {
		t.Fatalf("Write Radius message fail: %+v", err)
	}
	if _, _, err := radiusConnection.ReadFromUDP(buffer); err != nil {
		t.Fatalf("Read Radius message failed: %+v", err)
	}

	// ============================================
	// RADIUS: EAP-Response/5G-NAS carrying Security Mode Complete
	// ============================================
	identifier, err = ike_security.GenerateRandomUint8()
	if err != nil {
		t.Fatalf("Random number failed: %+v", err)
	}
	registrationRequestWith5GMM := GetRegistrationRequest(nasIE.RegType_InitialReg,
		mobileIdentity5GS, nil, ueSecurityCapability, ue.Get5GMMCapability(), nil, nil)
	smcComplete := GetSecurityModeComplete(registrationRequestWith5GMM)
	smcComplete, err = EncodeNasPduWithSecurity(ue, smcComplete,
		nasMessage.SecHdrTypeIntegrityProtectedAndCipheredWithNew5gNasSecCtx, true, true)
	assert.Nil(t, err)

	// Recompute AN-Parameters fresh here (rather than reusing the Registration step's
	// anParameters/anParametersLength), matching the reference test's own
	// tngfBuildEAP5GANParameters call at this point — pure function of mobileIdentity5GS,
	// same bytes, but avoids any risk of the earlier slice having been mutated in place
	// by an intervening append sharing its backing array.
	anParameters = buildEAP5GANParametersTNGF(0, mobileIdentityBuffer)
	anParametersLength = make([]byte, 2)
	binary.BigEndian.PutUint16(anParametersLength, uint16(len(anParameters)))

	eapVendorTypeData = make([]byte, 2)
	eapVendorTypeData[0] = ike_message.EAP5GType5GNAS
	eapVendorTypeData = append(eapVendorTypeData, anParametersLength...)
	eapVendorTypeData = append(eapVendorTypeData, anParameters...)
	nasLength = make([]byte, 2)
	binary.BigEndian.PutUint16(nasLength, uint16(len(smcComplete)))
	eapVendorTypeData = append(eapVendorTypeData, nasLength...)
	eapVendorTypeData = append(eapVendorTypeData, smcComplete...)

	eapPayload, err = marshalEAP5GNAS(identifier, eapVendorTypeData)
	if err != nil {
		t.Fatalf("Marshal EAP-5G-NAS fail: %+v", err)
	}
	radiusMsg, err = buildTngfAccessRequest(0x08, fixedAuthenticator, eapPayload)
	if err != nil {
		t.Fatalf("Build RADIUS Access-Request fail: %+v", err)
	}
	pkt, err = radiusMsg.Encode()
	if err != nil {
		t.Fatalf("Radius message encode fail: %+v", err)
	}
	if _, err := radiusConnection.WriteToUDP(pkt, tngfRadiusUDPAddr); err != nil {
		t.Fatalf("Write Radius message fail: %+v", err)
	}
	if _, _, err := radiusConnection.ReadFromUDP(buffer); err != nil {
		t.Fatalf("Read Radius message failed: %+v", err)
	}

	// ============================================
	// RADIUS: EAP-Response/5G-Notification -> EAP-Success
	// ============================================
	identifier, err = ike_security.GenerateRandomUint8()
	if err != nil {
		t.Fatalf("Random number failed: %+v", err)
	}
	eapPayload, err = marshalEAP5GNotification(identifier)
	if err != nil {
		t.Fatalf("Marshal EAP-5G-Notification fail: %+v", err)
	}
	radiusMsg, err = buildTngfAccessRequest(0x09, fixedAuthenticator, eapPayload)
	if err != nil {
		t.Fatalf("Build RADIUS Access-Request fail: %+v", err)
	}
	pkt, err = radiusMsg.Encode()
	if err != nil {
		t.Fatalf("Radius message encode fail: %+v", err)
	}
	if _, err := radiusConnection.WriteToUDP(pkt, tngfRadiusUDPAddr); err != nil {
		t.Fatalf("Write Radius message fail: %+v", err)
	}
	if _, _, err := radiusConnection.ReadFromUDP(buffer); err != nil {
		t.Fatalf("Read Radius message failed: %+v", err)
	}
	t.Log("RADIUS/EAP-5G authentication complete")

	// ============================================
	// IKE_SA_INIT
	// ============================================
	ikeInitiatorSPI := uint64(123123)
	initPayload := new(ike_message.IKEPayloadContainer)

	securityAssociation := initPayload.BuildSecurityAssociation()
	proposal := securityAssociation.Proposals.BuildProposal(1, ike_message.TypeIKE, nil)
	proposal.EncryptionAlgorithm.BuildTransform(ike_message.TypeEncryptionAlgorithm, ike_message.ENCR_NULL, nil, nil, nil)
	proposal.IntegrityAlgorithm.BuildTransform(ike_message.TypeIntegrityAlgorithm, ike_message.AUTH_HMAC_SHA1_96, nil, nil, nil)
	proposal.PseudorandomFunction.BuildTransform(ike_message.TypePseudorandomFunction, ike_message.PRF_HMAC_SHA1, nil, nil, nil)
	proposal.DiffieHellmanGroup.BuildTransform(ike_message.TypeDiffieHellmanGroup, ike_message.DH_2048_BIT_MODP, nil, nil, nil)

	generator := new(big.Int).SetUint64(dh.Group14Generator)
	factor, ok := new(big.Int).SetString(dh.Group14PrimeString, 16)
	if !ok {
		t.Fatalf("Generate key exchange data failed")
	}
	secret, err := ike_security.GenerateRandomNumber()
	if err != nil {
		t.Fatalf("Generate secret: %v", err)
	}
	localPublicKeyExchangeValue := new(big.Int).Exp(generator, secret, factor).Bytes()
	prependZero := make([]byte, len(factor.Bytes())-len(localPublicKeyExchangeValue))
	localPublicKeyExchangeValue = append(prependZero, localPublicKeyExchangeValue...)
	initPayload.BuildKeyExchange(ike_message.DH_2048_BIT_MODP, localPublicKeyExchangeValue)

	localNonceBigInt, err := ike_security.GenerateRandomNumber()
	if err != nil {
		t.Fatalf("Generate local nonce: %v", err)
	}
	localNonce := localNonceBigInt.Bytes()
	initPayload.BuildNonce(localNonce)

	ikeMessage := ike_message.NewMessage(ikeInitiatorSPI, 0, ike_message.IKE_SA_INIT, false, true, 0, *initPayload)
	ikeMessageData, err := ikeMessage.Encode()
	if err != nil {
		t.Fatalf("Encode IKE Message fail: %+v", err)
	}
	if _, err := udpConnection.WriteToUDP(ikeMessageData, tngfUDPAddr); err != nil {
		t.Fatalf("Write IKE message fail: %+v", err)
	}
	realMessage1, _ := ikeMessage.Encode()

	n, _, err = udpConnection.ReadFromUDP(buffer)
	if err != nil {
		t.Fatalf("Read IKE Message fail: %+v", err)
	}
	ikeMessage.Payloads.Reset()
	if err := ikeMessage.Decode(buffer[:n]); err != nil {
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
			i := 0
			for remotePublicKeyExchangeValue[i] == 0 {
			}
			remotePublicKeyExchangeValue = remotePublicKeyExchangeValue[i:]
			remotePublicKeyExchangeValueBig := new(big.Int).SetBytes(remotePublicKeyExchangeValue)
			sharedKeyExchangeData = new(big.Int).Exp(remotePublicKeyExchangeValueBig, secret, factor).Bytes()
		case ike_message.TypeNiNr:
			remoteNonce = ikePayload.(*ike_message.Nonce).NonceData
		}
	}

	ikeSA := &TNGFIKESecurityAssociation{
		LocalSPI:               ikeInitiatorSPI,
		RemoteSPI:              ikeMessage.ResponderSPI,
		InitiatorMessageID:     0,
		ResponderMessageID:     0,
		DhInfo:                 dh.DecodeTransform(proposal.DiffieHellmanGroup[0]),
		IntegInfo:              integ.DecodeTransform(proposal.IntegrityAlgorithm[0]),
		PrfInfo:                prf.DecodeTransform(proposal.PseudorandomFunction[0]),
		ConcatenatedNonce:      append(localNonce, remoteNonce...),
		DiffieHellmanSharedKey: sharedKeyExchangeData,
		ResponderSignedOctets:  append(realMessage1, remoteNonce...),
	}

	if err := tngfGenerateKeyForIKESA(ikeSA); err != nil {
		t.Fatalf("Generate key for IKE SA failed: %+v", err)
	}
	tngfue.TNGFIKESecurityAssociation = ikeSA

	// ============================================
	// IKE_AUTH (single round-trip: EAP-5G authentication already completed via RADIUS)
	// ============================================
	ikeSA.InitiatorMessageID++
	ikeMessage.IKEHeader = ike_message.NewHeader(ikeSA.LocalSPI, ikeSA.RemoteSPI, ike_message.IKE_AUTH,
		false, true, ikeSA.InitiatorMessageID, uint8(ike_message.NoNext), nil)
	ikeMessage.Payloads.Reset()

	var ikePayload ike_message.IKEPayloadContainer

	// Identification
	ikePayload.BuildIdentificationInitiator(ike_message.ID_KEY_ID, mobileIdentityBuffer)

	// Security Association
	securityAssociation = ikePayload.BuildSecurityAssociation()
	inboundSPI, err := tngfGenerateSPI(tngfue)
	if err != nil {
		t.Fatal(err)
	}
	proposal = securityAssociation.Proposals.BuildProposal(1, ike_message.TypeESP, inboundSPI)
	proposal.EncryptionAlgorithm.BuildTransform(ike_message.TypeEncryptionAlgorithm, ike_message.ENCR_NULL, nil, nil, nil)
	proposal.IntegrityAlgorithm.BuildTransform(ike_message.TypeIntegrityAlgorithm, ike_message.AUTH_HMAC_SHA1_96, nil, nil, nil)
	proposal.ExtendedSequenceNumbers.BuildTransform(ike_message.TypeExtendedSequenceNumbers, ike_message.ESN_DISABLE, nil, nil, nil)

	// Traffic Selector
	tsi := ikePayload.BuildTrafficSelectorInitiator()
	tsi.TrafficSelectors.BuildIndividualTrafficSelector(ike_message.TS_IPV4_ADDR_RANGE, 0, 0, 65535,
		[]byte{0, 0, 0, 0}, []byte{255, 255, 255, 255})
	tsr := ikePayload.BuildTrafficSelectorResponder()
	tsr.TrafficSelectors.BuildIndividualTrafficSelector(ike_message.TS_IPV4_ADDR_RANGE, 0, 0, 65535,
		[]byte{0, 0, 0, 0}, []byte{255, 255, 255, 255})

	// Authentication: derive Ktngf -> Ktipsec
	Ktngf, err := deriveKn3iwf(ue)
	if err != nil {
		t.Fatalf("Get Ktngf error: %+v", err)
	}
	Ktipsec, err := deriveKtipsec(Ktngf)
	if err != nil {
		t.Fatalf("Get Ktipsec error: %+v", err)
	}

	var idPayload ike_message.IKEPayloadContainer
	idPayload.BuildIdentificationInitiator(ike_message.ID_KEY_ID, mobileIdentityBuffer)
	idPayloadData, err := idPayload.Encode()
	if err != nil {
		t.Fatalf("Encode IKE payload failed: %+v", err)
	}
	if _, err := ikeSA.Prf_i.Write(idPayloadData[4:]); err != nil {
		t.Fatalf("Pseudorandom function write error: %+v", err)
	}
	ikeSA.ResponderSignedOctets = append(ikeSA.ResponderSignedOctets, ikeSA.Prf_i.Sum(nil)...)

	pseudorandomFunction := ikeSA.PrfInfo.Init(Ktipsec)
	if _, err := pseudorandomFunction.Write([]byte("Key Pad for IKEv2")); err != nil {
		t.Fatalf("Pseudorandom function write error: %+v", err)
	}
	authSecret := pseudorandomFunction.Sum(nil)
	pseudorandomFunction = ikeSA.PrfInfo.Init(authSecret)
	pseudorandomFunction.Reset()
	if _, err := pseudorandomFunction.Write(ikeSA.ResponderSignedOctets); err != nil {
		t.Fatalf("Pseudorandom function write error: %+v", err)
	}
	ikePayload.BuildAuthentication(ike_message.SharedKeyMesageIntegrityCode, pseudorandomFunction.Sum(nil))

	// Configuration Request
	configurationRequest := ikePayload.BuildConfiguration(ike_message.CFG_REQUEST)
	configurationRequest.ConfigurationAttribute.BuildConfigurationAttribute(ike_message.INTERNAL_IP4_ADDRESS, nil)

	if err := tngfEncryptProcedure(ikeSA, ikePayload, ikeMessage); err != nil {
		t.Fatalf("Encrypt IKE message failed: %+v", err)
	}

	ikeMessageData, err = ikeMessage.Encode()
	if err != nil {
		t.Fatalf("Encode IKE message failed: %+v", err)
	}
	if _, err := udpConnection.WriteToUDP(ikeMessageData, tngfUDPAddr); err != nil {
		t.Fatalf("Write IKE message failed: %+v", err)
	}
	tngfue.CreateHalfChildSA(ikeSA.InitiatorMessageID, binary.BigEndian.Uint32(inboundSPI))

	n, _, err = udpConnection.ReadFromUDP(buffer)
	if err != nil {
		t.Fatalf("Read IKE message failed: %+v", err)
	}
	ikeMessage.Payloads.Reset()
	if err := ikeMessage.Decode(buffer[:n]); err != nil {
		t.Fatalf("Decode IKE message failed: %+v", err)
	}

	encryptedPayload, ok := ikeMessage.Payloads[0].(*ike_message.Encrypted)
	if !ok {
		t.Fatalf("Received payload is not an encrypted payload")
	}
	decryptedIKEPayload, err := tngfDecryptProcedure(ikeSA, ikeMessage, encryptedPayload)
	if err != nil {
		t.Fatalf("Decrypt IKE message failed: %+v", err)
	}

	var responseSecurityAssociation *ike_message.SecurityAssociation
	var responseTrafficSelectorInitiator *ike_message.TrafficSelectorInitiator
	var responseTrafficSelectorResponder *ike_message.TrafficSelectorResponder
	var responseConfiguration *ike_message.Configuration
	tngfNASAddr := new(net.TCPAddr)

	for _, ikePayload := range decryptedIKEPayload {
		switch ikePayload.Type() {
		case ike_message.TypeAUTH:
			t.Log("Get Authentication from TNGF")
		case ike_message.TypeSA:
			responseSecurityAssociation = ikePayload.(*ike_message.SecurityAssociation)
			ikeSA.IKEAuthResponseSA = responseSecurityAssociation
		case ike_message.TypeTSi:
			responseTrafficSelectorInitiator = ikePayload.(*ike_message.TrafficSelectorInitiator)
		case ike_message.TypeTSr:
			responseTrafficSelectorResponder = ikePayload.(*ike_message.TrafficSelectorResponder)
		case ike_message.TypeN:
			notification := ikePayload.(*ike_message.Notification)
			if notification.NotifyMessageType == ike_message.Vendor3GPPNotifyTypeNAS_IP4_ADDRESS {
				tngfNASAddr.IP = net.IPv4(notification.NotificationData[0], notification.NotificationData[1],
					notification.NotificationData[2], notification.NotificationData[3])
			}
			if notification.NotifyMessageType == ike_message.Vendor3GPPNotifyTypeNAS_TCP_PORT {
				tngfNASAddr.Port = int(binary.BigEndian.Uint16(notification.NotificationData))
			}
		case ike_message.TypeCP:
			responseConfiguration = ikePayload.(*ike_message.Configuration)
			if responseConfiguration.ConfigurationType == ike_message.CFG_REPLY {
				for _, configAttr := range responseConfiguration.ConfigurationAttribute {
					if configAttr.Type == ike_message.INTERNAL_IP4_ADDRESS {
						tngfueInnerAddr.IP = configAttr.Value
					}
					if configAttr.Type == ike_message.INTERNAL_IP4_NETMASK {
						tngfueInnerAddr.Mask = configAttr.Value
					}
				}
			}
		}
	}

	OutboundSPI := binary.BigEndian.Uint32(ikeSA.IKEAuthResponseSA.Proposals[0].SPI)
	childSecurityAssociationContext, err := tngfue.CompleteChildSA(ikeSA.InitiatorMessageID, OutboundSPI, ikeSA.IKEAuthResponseSA)
	if err != nil {
		t.Fatalf("Create child security association context failed: %+v", err)
	}
	if err := tngfParseIPAddressInformationToChildSecurityAssociation(childSecurityAssociationContext,
		responseTrafficSelectorInitiator.TrafficSelectors[0],
		responseTrafficSelectorResponder.TrafficSelectors[0]); err != nil {
		t.Fatalf("Parse IP address to child security association failed: %+v", err)
	}
	// Select TCP traffic
	childSecurityAssociationContext.SelectedIPProtocol = unix.IPPROTO_TCP

	if err := childSecurityAssociationContext.GenerateKeyForChildSA(ikeSA); err != nil {
		t.Fatalf("Generate key for child SA failed: %+v", err)
	}

	// Setup interface for ipsec (shared by both the TCP NAS-signaling child SA and
	// the first PDU session's GRE child SA, matching the reference test)
	newXfrmiName := fmt.Sprintf("%s-default", tngfueInfo_XfrmiName)
	linkIPSec, err := setupIPsecXfrmi(newXfrmiName, tngfueInfo_IPSecIfaceName, tngfueInfo_XfrmiId, tngfueInnerAddr)
	if err != nil {
		t.Fatalf("Setup XFRM interface %s fail: %+v", newXfrmiName, err)
	}
	defer func() {
		if err := netlink.LinkDel(linkIPSec); err != nil {
			t.Fatalf("Delete XFRM interface %s fail: %+v", newXfrmiName, err)
		} else {
			t.Logf("Delete XFRM interface: %s", newXfrmiName)
		}
	}()

	if err := tngfApplyXFRMRule(true, tngfueInfo_XfrmiId, childSecurityAssociationContext); err != nil {
		t.Fatalf("Applying XFRM rules failed: %+v", err)
	}
	defer func() {
		_ = netlink.XfrmPolicyFlush()
		_ = netlink.XfrmStateFlush(netlink.XFRM_PROTO_IPSEC_ANY)
	}()

	// Waiting for downlink data to be stored in the cache, then establishing a TCP connection.
	time.Sleep(1 * time.Second)

	localTCPAddr := &net.TCPAddr{IP: tngfueInnerAddr.IP}
	tcpConnWithTNGF, err := net.DialTCP("tcp", localTCPAddr, tngfNASAddr)
	if err != nil {
		t.Fatal(err)
	}
	t.Log("Establish TCP connection with TNGF successfully")
	tcpConnWithTNGF.SetReadDeadline(time.Now().Add(20 * time.Second))

	nasEnv := make([]byte, 65535)
	n, err = tcpConnWithTNGF.Read(nasEnv)
	if err != nil {
		t.Fatal(err)
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
	t.Logf("Get Registration Accept Message:\n %+v", spew.Sdump(nasMsg))

	// send NAS Registration Complete Msg
	pdu := GetRegistrationComplete(nil)
	pdu, err = EncodeNasPduInEnvelopeWithSecurity(ue, pdu, nasMessage.SecHdrTypeIntegrityProtectedAndCiphered, true, false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tcpConnWithTNGF.Write(pdu); err != nil {
		t.Fatal(err)
	}

	time.Sleep(1 * time.Second)

	// ============================================
	// UE requests the PDU session setup
	// ============================================
	sNssai := models.Snssai{
		Sst: SST,
		Sd:  tngfueInfo_SmPolicy_SNSSAI_SD,
	}
	var pduSessionId uint8 = 1

	pdu = GetUlNasTransport_PduSessionEstablishmentRequest(pduSessionId, nasIE.ReqType_InitialReq,
		"internet", &sNssai)
	pdu, err = EncodeNasPduInEnvelopeWithSecurity(ue, pdu, nasMessage.SecHdrTypeIntegrityProtectedAndCiphered, true, false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tcpConnWithTNGF.Write(pdu); err != nil {
		t.Fatal(err)
	}

	// Receive TNGF reply (CREATE_CHILD_SA for user-plane GRE)
	n, _, err = udpConnection.ReadFromUDP(buffer)
	if err != nil {
		t.Fatalf("Read IKE Message fail: %+v", err)
	}
	ikeMessage.Payloads.Reset()
	if err := ikeMessage.Decode(buffer[:n]); err != nil {
		t.Fatalf("Decode IKE Message fail: %+v", err)
	}
	encryptedPayload, ok = ikeMessage.Payloads[0].(*ike_message.Encrypted)
	if !ok {
		t.Fatal("Received packet is not an encrypted payload")
	}
	decryptedIKEPayload, err = tngfDecryptProcedure(ikeSA, ikeMessage, encryptedPayload)
	if err != nil {
		t.Fatal(err)
	}

	var QoSInfo *PDUQoSInfo
	var upIPAddr net.IP
	for _, ikePayload := range decryptedIKEPayload {
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
					if QoSInfo.isDSCPSpecified {
						t.Logf("DSCP is specified but test not support")
					}
				} else {
					t.Logf("%+v", err)
				}
			}
			if notification.NotifyMessageType == ike_message.Vendor3GPPNotifyTypeUP_IP4_ADDRESS {
				upIPAddr = notification.NotificationData[:4]
				t.Logf("UP IP Address: %+v", upIPAddr)
			}
		case ike_message.TypeNiNr:
			responseNonce := ikePayload.(*ike_message.Nonce)
			ikeSA.ConcatenatedNonce = responseNonce.NonceData
		}
	}

	// IKE CREATE_CHILD_SA response
	respInitiatorSPI, respResponderSPI := ikeMessage.InitiatorSPI, ikeMessage.ResponderSPI
	ikeSA.ResponderMessageID = ikeMessage.MessageID
	ikeMessage.IKEHeader = ike_message.NewHeader(respInitiatorSPI, respResponderSPI, ike_message.CREATE_CHILD_SA,
		true, true, ikeSA.ResponderMessageID, uint8(ike_message.NoNext), nil)
	ikeMessage.Payloads.Reset()

	ikePayload.Reset()

	inboundSPI, err = tngfGenerateSPI(tngfue)
	if err != nil {
		t.Fatal(err)
	}
	responseSecurityAssociation.Proposals[0].SPI = inboundSPI
	ikePayload = append(ikePayload, responseSecurityAssociation)
	ikePayload = append(ikePayload, responseTrafficSelectorInitiator)
	ikePayload = append(ikePayload, responseTrafficSelectorResponder)

	localNonceBigInt, err = ike_security.GenerateRandomNumber()
	if err != nil {
		t.Fatalf("Generate local nonce: %v", err)
	}
	localNonce = localNonceBigInt.Bytes()
	ikeSA.ConcatenatedNonce = append(ikeSA.ConcatenatedNonce, localNonce...)
	ikePayload.BuildNonce(localNonce)

	if err := tngfEncryptProcedure(ikeSA, ikePayload, ikeMessage); err != nil {
		t.Fatalf("Encrypt IKE message failed: %+v", err)
	}

	ikeMessageData, err = ikeMessage.Encode()
	if err != nil {
		t.Fatalf("Encode IKE Message fail: %+v", err)
	}
	if _, err := udpConnection.WriteToUDP(ikeMessageData, tngfUDPAddr); err != nil {
		t.Fatalf("Write IKE message failed: %+v", err)
	}

	tngfue.CreateHalfChildSA(ikeSA.ResponderMessageID, binary.BigEndian.Uint32(inboundSPI))
	childSecurityAssociationContextUserPlane, err := tngfue.CompleteChildSA(
		ikeSA.ResponderMessageID, OutboundSPI, responseSecurityAssociation)
	if err != nil {
		t.Fatalf("Create child security association context failed: %+v", err)
	}
	if err := tngfParseIPAddressInformationToChildSecurityAssociation(childSecurityAssociationContextUserPlane,
		responseTrafficSelectorResponder.TrafficSelectors[0],
		responseTrafficSelectorInitiator.TrafficSelectors[0]); err != nil {
		t.Fatalf("Parse IP address to child security association failed: %+v", err)
	}
	// Select GRE traffic
	childSecurityAssociationContextUserPlane.SelectedIPProtocol = unix.IPPROTO_GRE

	if err := childSecurityAssociationContextUserPlane.GenerateKeyForChildSA(ikeSA); err != nil {
		t.Fatalf("Generate key for child SA failed: %+v", err)
	}

	if err := tngfApplyXFRMRule(false, tngfueInfo_XfrmiId, childSecurityAssociationContextUserPlane); err != nil {
		t.Fatalf("Applying XFRM rules failed: %+v", err)
	}

	var pduAddress net.IP
	if n, err := tcpConnWithTNGF.Read(buffer); err != nil {
		t.Fatalf("Read NAS Message Fail: %+v", err)
	} else {
		nasMsg, err := DecodePDUSessionEstablishmentAccept(ue, n, buffer)
		if err != nil {
			t.Fatalf("DecodePDUSessionEstablishmentAccept Fail: %+v", err)
		}
		spew.Config.Indent = "\t"
		t.Log("Dump DecodePDUSessionEstablishmentAccept:\n", spew.Sdump(nasMsg))
		pduAddress, err = GetPDUAddress(nasMsg)
		if err != nil {
			t.Fatalf("GetPDUAddress Fail: %+v", err)
		}
		t.Logf("PDU Address: %s", pduAddress.String())
	}

	newGREName := fmt.Sprintf("%s-id-%d", tngfueInfo_GreIfaceName, tngfueInfo_XfrmiId)
	linkGRE, err := setupGreTunnel(newGREName, newXfrmiName, tngfueInnerAddr.IP, upIPAddr, pduAddress, QoSInfo, t)
	if err != nil {
		t.Fatalf("Setup GRE tunnel %s Fail %+v", newGREName, err)
	}
	defer func() {
		_ = netlink.LinkDel(linkGRE)
		t.Logf("Delete interface: %s", linkGRE.Attrs().Name)
	}()

	// Add a host route for the ping test's target (EIGHT_IP, see below) via the GRE
	// tunnel. The reference test adds a full 0.0.0.0/0 default route instead, but this
	// container already has a default route via the docker bridge (same metric), so a
	// second 0.0.0.0/0 route collides with EEXIST (same reasoning as TestN3iwf's
	// identical fix). A /32 host route wins on longest-prefix-match without colliding.
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
	// Verify user-plane connectivity with a real ping through the GRE/IPsec tunnel.
	// Ping EIGHT_IP (the already-verified-reachable external address other IT tests
	// use) rather than the reference test's 10.60.0.101, which nothing listens on in
	// this environment (same reasoning as TestN3iwf). Source is the PDU session's own
	// allocated address.
	// ============================================
	pinger, err := ping.NewPinger(EIGHT_IP)
	if err != nil {
		t.Fatal(err)
	}
	pinger.SetPrivileged(true)
	pinger.OnRecv = func(pkt *ping.Packet) {
		t.Logf("%d bytes from %s: icmp_seq=%d time=%v", pkt.Nbytes, pkt.IPAddr, pkt.Seq, pkt.Rtt)
	}
	pinger.OnFinish = func(stats *ping.Statistics) {
		t.Logf("--- %s ping statistics ---", stats.Addr)
		t.Logf("%d packets transmitted, %d packets received, %v%% packet loss",
			stats.PacketsSent, stats.PacketsRecv, stats.PacketLoss)
		t.Logf("round-trip min/avg/max/stddev = %v/%v/%v/%v",
			stats.MinRtt, stats.AvgRtt, stats.MaxRtt, stats.StdDevRtt)
	}
	pinger.Count = 5
	pinger.Timeout = 10 * time.Second
	pinger.Source = pduAddress.String()

	time.Sleep(3 * time.Second)
	pinger.Run()
	time.Sleep(1 * time.Second)

	stats := pinger.Statistics()
	if stats.PacketsSent != stats.PacketsRecv {
		t.Fatal("Ping Failed")
	}
}
