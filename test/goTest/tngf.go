package test

// TNGF (trusted non-3GPP access gateway) IKEv2/XFRM/GRE client-side logic, ported from
// free5gc/test/tngf_test.go. TNGF differs from N3IWF (non3gpp.go) in two ways that rule
// out reusing non3gpp.go's types directly:
//
//  1. EAP-5G is relayed over RADIUS (see radius.go), completing authentication *before*
//     IKE_SA_INIT even starts, rather than being carried inside repeated IKE_AUTH
//     round-trips.
//  2. TNGF always proposes ENCR_NULL (no encryption, integrity-only) for both the IKE SA
//     and the Child SAs. github.com/free5gc/ike@v1.2.1's security.IKESAKey/ChildSAKey
//     can't represent this: their EncrInfo/EncrKInfo fields are typed to the encr
//     package's ENCRType/ENCRKType interfaces, which only implement AES-CBC and can't be
//     satisfied from outside that package (ENCRType has an unexported method). So this
//     file defines its own minimal IKE/Child SA key types instead of embedding
//     ike_security.IKESAKey/ChildSAKey, deriving keys with the same underlying (and
//     exported) dh/prf/integ/lib primitives non3gpp.go uses, and treating "encryption"
//     as a no-op since ENCR_NULL's key length is 0 — only the HMAC-SHA1-96 integrity
//     checksum actually protects the message. This still depends on nothing from
//     free5gc/tngf's own source tree.

import (
	"crypto/hmac"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"net"

	"github.com/vishvananda/netlink"

	ike_message "github.com/free5gc/ike/message"
	ike_security "github.com/free5gc/ike/security"
	"github.com/free5gc/ike/security/dh"
	"github.com/free5gc/ike/security/integ"
	"github.com/free5gc/ike/security/lib"
	"github.com/free5gc/ike/security/prf"

	"github.com/free5gc/util/ueauth"
)

var (
	tngfueInfo_IPSecIfaceAddr     = IT_IP
	tngfueInfo_SmPolicy_SNSSAI_SD = SD
	tngfueInfo_IPSecIfaceName     = IT_IPSEC_IFACE_NAME
	tngfueInfo_XfrmiName          = "ipsec"
	tngfueInfo_XfrmiId            = uint32(2)
	tngfueInfo_GreIfaceName       = "gretun"
	tngfueInnerAddr               = new(net.IPNet)
)

// tngfChecksumLength is the truncated HMAC-SHA1-96 output length TNGF uses for both the
// IKE SA and the Child SAs (RFC 7296's AUTH_HMAC_SHA1_96).
const tngfChecksumLength = 12

type TNGFUe struct {
	TNGFIKESecurityAssociation           *TNGFIKESecurityAssociation
	TNGFChildSecurityAssociation         map[uint32]*TNGFChildSecurityAssociation // inbound SPI as key
	TemporaryExchangeMsgIDChildSAMapping map[uint32]*TNGFChildSecurityAssociation // message ID as key
}

type TNGFIKESecurityAssociation struct {
	// SPI
	LocalSPI  uint64
	RemoteSPI uint64

	// Message ID
	InitiatorMessageID uint32
	ResponderMessageID uint32

	// Transforms (no EncrInfo: TNGF always proposes ENCR_NULL, so SK_ei/SK_er have
	// zero length and there's nothing to decode/store there)
	DhInfo    dh.DHType
	IntegInfo integ.INTEGType
	PrfInfo   prf.PRFType

	// Keys (RFC 7296 section 2.14)
	SK_d  []byte
	SK_ai []byte
	SK_ar []byte
	SK_pi []byte
	SK_pr []byte

	Prf_d   hash.Hash
	Prf_i   hash.Hash
	Prf_r   hash.Hash
	Integ_i hash.Hash
	Integ_r hash.Hash

	// Authentication data
	ResponderSignedOctets []byte

	// Used for key generating
	ConcatenatedNonce      []byte
	DiffieHellmanSharedKey []byte

	// Temporary data stored for use in later exchange
	IKEAuthResponseSA *ike_message.SecurityAssociation
}

type TNGFChildSecurityAssociation struct {
	// SPI
	InboundSPI  uint32
	OutboundSPI uint32

	// IP address
	PeerPublicIPAddr  net.IP
	LocalPublicIPAddr net.IP

	// Traffic selector
	SelectedIPProtocol    uint8
	TrafficSelectorLocal  net.IPNet
	TrafficSelectorRemote net.IPNet

	// Transform IDs from the negotiated proposal, used only to pick the XFRM
	// algorithm name via XFRMEncryptionAlgorithmType/XFRMIntegrityAlgorithmType
	// (non3gpp.go). TNGF always negotiates ENCR_NULL + AUTH_HMAC_SHA1_96.
	EncrTransformID  uint16
	IntegTransformID uint16
	NeedESN          bool

	InitiatorToResponderEncryptionKey []byte
	InitiatorToResponderIntegrityKey  []byte
	ResponderToInitiatorEncryptionKey []byte
	ResponderToInitiatorIntegrityKey  []byte
}

func (ue *TNGFUe) CreateHalfChildSA(msgID, inboundSPI uint32) {
	childSA := new(TNGFChildSecurityAssociation)
	childSA.InboundSPI = inboundSPI
	ue.TemporaryExchangeMsgIDChildSAMapping[msgID] = childSA
}

func (ue *TNGFUe) CompleteChildSA(msgID uint32, outboundSPI uint32,
	chosenSecurityAssociation *ike_message.SecurityAssociation,
) (*TNGFChildSecurityAssociation, error) {
	childSA, ok := ue.TemporaryExchangeMsgIDChildSAMapping[msgID]
	if !ok {
		return nil, fmt.Errorf("CompleteChildSA(): no half child SA for message ID %d", msgID)
	}
	delete(ue.TemporaryExchangeMsgIDChildSAMapping, msgID)

	if chosenSecurityAssociation == nil || len(chosenSecurityAssociation.Proposals) == 0 {
		return nil, errors.New("CompleteChildSA(): no proposal")
	}
	proposal := chosenSecurityAssociation.Proposals[0]
	if len(proposal.EncryptionAlgorithm) == 0 {
		return nil, errors.New("CompleteChildSA(): no encryption algorithm in proposal")
	}
	childSA.EncrTransformID = proposal.EncryptionAlgorithm[0].TransformID
	if len(proposal.IntegrityAlgorithm) > 0 {
		childSA.IntegTransformID = proposal.IntegrityAlgorithm[0].TransformID
	}
	childSA.OutboundSPI = outboundSPI

	ue.TNGFChildSecurityAssociation[childSA.InboundSPI] = childSA
	return childSA, nil
}

// GenerateKeyForChildSA derives the Child SA's directional keys (RFC 7296 section
// 2.17). TNGF's ENCR_NULL means the encryption key length is always 0; only the
// HMAC-SHA1-96 integrity keys are non-empty.
func (childSA *TNGFChildSecurityAssociation) GenerateKeyForChildSA(ikeSA *TNGFIKESecurityAssociation) error {
	if ikeSA.Prf_d == nil {
		return errors.New("GenerateKeyForChildSA: no key deriving key")
	}

	lengthIntegrityKeyIPSec := 0
	if childSA.IntegTransformID == ike_message.AUTH_HMAC_SHA1_96 {
		lengthIntegrityKeyIPSec = 20
	}
	totalKeyLength := lengthIntegrityKeyIPSec * 2

	keyStream := lib.PrfPlus(ikeSA.Prf_d, ikeSA.ConcatenatedNonce, totalKeyLength)
	if keyStream == nil {
		return errors.New("GenerateKeyForChildSA: PrfPlus failed")
	}

	childSA.InitiatorToResponderIntegrityKey = append([]byte{}, keyStream[:lengthIntegrityKeyIPSec]...)
	keyStream = keyStream[lengthIntegrityKeyIPSec:]
	childSA.ResponderToInitiatorIntegrityKey = append([]byte{}, keyStream[:lengthIntegrityKeyIPSec]...)

	return nil
}

func tngfGenerateSPI(ue *TNGFUe) ([]byte, error) {
	var spi uint32
	spiByte := make([]byte, 4)
	for {
		randomBigInt, err := ike_security.GenerateRandomNumber()
		if err != nil {
			return nil, fmt.Errorf("tngfGenerateSPI(): %w", err)
		}
		randomUint64 := randomBigInt.Uint64()
		if _, ok := ue.TNGFChildSecurityAssociation[uint32(randomUint64)]; !ok {
			spi = uint32(randomUint64)
			binary.BigEndian.PutUint32(spiByte, spi)
			break
		}
	}
	return spiByte, nil
}

func setupRadiusSocket() (*net.UDPConn, error) {
	bindAddr := fmt.Sprintf("%s:48744", tngfueInfo_IPSecIfaceAddr)
	udpAddr, err := net.ResolveUDPAddr("udp", bindAddr)
	if err != nil {
		return nil, fmt.Errorf("resolve UDP address failed: %w", err)
	}
	udpListener, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return nil, fmt.Errorf("listen UDP failed: %w", err)
	}
	return udpListener, nil
}

// concatenateNonceAndSPI builds the "Ni | Nr | SPIi | SPIr" seed used both for
// SKEYSEED derivation and prf+ (RFC 7296 sections 1.3, 2.14).
func concatenateNonceAndSPI(nonce []byte, spiInitiator, spiResponder uint64) []byte {
	var newSlice []byte
	spi := make([]byte, 8)

	newSlice = append(newSlice, nonce...)
	binary.BigEndian.PutUint64(spi, spiInitiator)
	newSlice = append(newSlice, spi...)
	binary.BigEndian.PutUint64(spi, spiResponder)
	newSlice = append(newSlice, spi...)

	return newSlice
}

// tngfGenerateKeyForIKESA derives the IKE SA keys (RFC 7296 sections 1.3, 1.4, 2.14).
// SK_ei/SK_er are intentionally never derived: TNGF's ENCR_NULL has a 0-byte key.
func tngfGenerateKeyForIKESA(ikeSA *TNGFIKESecurityAssociation) error {
	if ikeSA.PrfInfo == nil {
		return errors.New("no pseudorandom function specified")
	}
	if ikeSA.IntegInfo == nil {
		return errors.New("no integrity algorithm specified")
	}
	if len(ikeSA.ConcatenatedNonce) == 0 {
		return errors.New("no concatenated nonce data")
	}
	if len(ikeSA.DiffieHellmanSharedKey) == 0 {
		return errors.New("no Diffie-Hellman shared key")
	}

	lengthSKd := ikeSA.PrfInfo.GetKeyLength()
	lengthSKai := ikeSA.IntegInfo.GetKeyLength()
	lengthSKar := lengthSKai
	lengthSKpi, lengthSKpr := lengthSKd, lengthSKd
	totalKeyLength := lengthSKd + lengthSKai + lengthSKar + lengthSKpi + lengthSKpr

	prfHash := ikeSA.PrfInfo.Init(ikeSA.ConcatenatedNonce)
	if _, err := prfHash.Write(ikeSA.DiffieHellmanSharedKey); err != nil {
		return err
	}
	skeyseed := prfHash.Sum(nil)

	seed := concatenateNonceAndSPI(ikeSA.ConcatenatedNonce, ikeSA.LocalSPI, ikeSA.RemoteSPI)

	keyStream := lib.PrfPlus(ikeSA.PrfInfo.Init(skeyseed), seed, totalKeyLength)
	if keyStream == nil {
		return errors.New("PrfPlus failed")
	}

	ikeSA.SK_d = keyStream[:lengthSKd]
	keyStream = keyStream[lengthSKd:]
	ikeSA.SK_ai = keyStream[:lengthSKai]
	keyStream = keyStream[lengthSKai:]
	ikeSA.SK_ar = keyStream[:lengthSKar]
	keyStream = keyStream[lengthSKar:]
	ikeSA.SK_pi = keyStream[:lengthSKpi]
	keyStream = keyStream[lengthSKpi:]
	ikeSA.SK_pr = keyStream[:lengthSKpr]

	ikeSA.Prf_d = ikeSA.PrfInfo.Init(ikeSA.SK_d)
	ikeSA.Prf_i = ikeSA.PrfInfo.Init(ikeSA.SK_pi)
	ikeSA.Prf_r = ikeSA.PrfInfo.Init(ikeSA.SK_pr)
	ikeSA.Integ_i = ikeSA.IntegInfo.Init(ikeSA.SK_ai)
	ikeSA.Integ_r = ikeSA.IntegInfo.Init(ikeSA.SK_ar)

	return nil
}

func tngfCalculateChecksum(integHash hash.Hash, data []byte) ([]byte, error) {
	integHash.Reset()
	if _, err := integHash.Write(data); err != nil {
		return nil, err
	}
	return integHash.Sum(nil)[:tngfChecksumLength], nil
}

// tngfEncryptProcedure builds the SK (Encrypted) payload for an outgoing IKE message.
// ENCR_NULL means there's no actual cipher transformation, but RFC 7296 section 3.14's
// Encrypted payload format still mandates a trailing Pad Length octet before the
// checksum (the free5gc/ike AES-CBC path adds the same field via PKCS7 padding — see
// encr.EncrAesCbcCrypto.Encrypt/Decrypt); with no block-size alignment needed, that
// means exactly one zero byte (0 padding bytes, plus the length octet itself).
func tngfEncryptProcedure(ikeSA *TNGFIKESecurityAssociation, ikePayload ike_message.IKEPayloadContainer,
	ikeMessage *ike_message.IKEMessage,
) error {
	if ikeSA.Integ_i == nil {
		return errors.New("no initiator integrity key")
	}

	plainText, err := ikePayload.Encode()
	if err != nil {
		return fmt.Errorf("encoding IKE payload failed: %w", err)
	}
	plainText = append(plainText, 0x00) // Pad Length octet: 0 padding bytes

	encryptedData := append(plainText, make([]byte, tngfChecksumLength)...)
	var nextPayloadType ike_message.IkePayloadType
	if len(ikePayload) == 0 {
		nextPayloadType = ike_message.NoNext
	} else {
		nextPayloadType = ikePayload[0].Type()
	}
	sk := ikeMessage.Payloads.BuildEncrypted(nextPayloadType, encryptedData)

	ikeMessageData, err := ikeMessage.Encode()
	if err != nil {
		return fmt.Errorf("encoding IKE message failed: %w", err)
	}
	checksum, err := tngfCalculateChecksum(ikeSA.Integ_i, ikeMessageData[:len(ikeMessageData)-tngfChecksumLength])
	if err != nil {
		return err
	}
	checksumField := sk.EncryptedData[len(sk.EncryptedData)-tngfChecksumLength:]
	copy(checksumField, checksum)
	return nil
}

// tngfDecryptProcedure verifies the checksum and unwraps an incoming SK payload.
// ENCR_NULL means there's no cipher transformation to reverse, but the trailing Pad
// Length octet tngfEncryptProcedure adds still has to be stripped along with the
// checksum (see that function's doc comment).
func tngfDecryptProcedure(ikeSA *TNGFIKESecurityAssociation, ikeMessage *ike_message.IKEMessage,
	encryptedPayload *ike_message.Encrypted,
) (ike_message.IKEPayloadContainer, error) {
	if ikeSA.Integ_r == nil {
		return nil, errors.New("no responder integrity key")
	}
	if len(encryptedPayload.EncryptedData) < tngfChecksumLength {
		return nil, errors.New("encrypted payload too short")
	}

	checksum := encryptedPayload.EncryptedData[len(encryptedPayload.EncryptedData)-tngfChecksumLength:]

	ikeMessageData, err := ikeMessage.Encode()
	if err != nil {
		return nil, fmt.Errorf("encoding IKE message failed: %w", err)
	}

	expectedChecksum, err := tngfCalculateChecksum(ikeSA.Integ_r,
		ikeMessageData[:len(ikeMessageData)-tngfChecksumLength])
	if err != nil {
		return nil, err
	}
	if !hmac.Equal(checksum, expectedChecksum) {
		return nil, errors.New("checksum failed, drop")
	}

	withoutChecksum := encryptedPayload.EncryptedData[:len(encryptedPayload.EncryptedData)-tngfChecksumLength]
	if len(withoutChecksum) < 1 {
		return nil, errors.New("encrypted payload missing pad length octet")
	}
	padLength := int(withoutChecksum[len(withoutChecksum)-1])
	plainTextEnd := len(withoutChecksum) - 1 - padLength
	if plainTextEnd < 0 {
		return nil, errors.New("invalid pad length")
	}
	plainText := withoutChecksum[:plainTextEnd]

	var decryptedIKEPayload ike_message.IKEPayloadContainer
	if err := decryptedIKEPayload.Decode(encryptedPayload.NextPayload, plainText); err != nil {
		return nil, fmt.Errorf("decoding decrypted payload failed: %w", err)
	}
	return decryptedIKEPayload, nil
}

// deriveKtipsec derives Ktipsec from Ktngf (TS 33.501), the extra KDF step TNGF's
// trusted-access AUTH payload needs beyond what N3IWF's Kn3iwf-based AUTH does
// (deriveKn3iwf in non3gpp.go computes the identical Ktngf formula under its N3IWF
// name — TS 33.501 uses the same FC for both).
func deriveKtipsec(Ktngf []byte) ([]byte, error) {
	p0 := []byte{0x01}
	return ueauth.GetKDFValue(Ktngf, ueauth.FC_FOR_KTIPSEC_KTNAP_DERIVATION, p0, ueauth.KDFLen(p0))
}

func tngfParseIPAddressInformationToChildSecurityAssociation(
	childSA *TNGFChildSecurityAssociation,
	trafficSelectorLocal *ike_message.IndividualTrafficSelector,
	trafficSelectorRemote *ike_message.IndividualTrafficSelector,
) error {
	if childSA == nil {
		return errors.New("childSA is nil")
	}

	childSA.PeerPublicIPAddr = net.ParseIP(TNGF_IP)
	childSA.LocalPublicIPAddr = net.ParseIP(tngfueInfo_IPSecIfaceAddr)

	childSA.TrafficSelectorLocal = net.IPNet{
		IP:   trafficSelectorLocal.StartAddress,
		Mask: []byte{255, 255, 255, 255},
	}
	childSA.TrafficSelectorRemote = net.IPNet{
		IP:   trafficSelectorRemote.StartAddress,
		Mask: []byte{255, 255, 255, 255},
	}
	return nil
}

// tngfApplyXFRMRule mirrors applyXFRMRule (non3gpp.go), adapted to
// TNGFChildSecurityAssociation's plain transform-ID fields (see the type's doc comment
// for why it can't embed ike_security.ChildSAKey).
func tngfApplyXFRMRule(ueIsInitiator bool, ifId uint32, childSA *TNGFChildSecurityAssociation) error {
	var xfrmEncryptionAlgorithm, xfrmIntegrityAlgorithm *netlink.XfrmStateAlgo
	if ueIsInitiator {
		xfrmEncryptionAlgorithm = &netlink.XfrmStateAlgo{
			Name: XFRMEncryptionAlgorithmType(childSA.EncrTransformID).String(),
			Key:  childSA.ResponderToInitiatorEncryptionKey,
		}
		if childSA.IntegTransformID != 0 {
			xfrmIntegrityAlgorithm = &netlink.XfrmStateAlgo{
				Name: XFRMIntegrityAlgorithmType(childSA.IntegTransformID).String(),
				Key:  childSA.ResponderToInitiatorIntegrityKey,
			}
		}
	} else {
		xfrmEncryptionAlgorithm = &netlink.XfrmStateAlgo{
			Name: XFRMEncryptionAlgorithmType(childSA.EncrTransformID).String(),
			Key:  childSA.InitiatorToResponderEncryptionKey,
		}
		if childSA.IntegTransformID != 0 {
			xfrmIntegrityAlgorithm = &netlink.XfrmStateAlgo{
				Name: XFRMIntegrityAlgorithmType(childSA.IntegTransformID).String(),
				Key:  childSA.InitiatorToResponderIntegrityKey,
			}
		}
	}

	xfrmState := new(netlink.XfrmState)
	xfrmState.Src = childSA.PeerPublicIPAddr
	xfrmState.Dst = childSA.LocalPublicIPAddr
	xfrmState.Proto = netlink.XFRM_PROTO_ESP
	xfrmState.Mode = netlink.XFRM_MODE_TUNNEL
	xfrmState.Spi = int(childSA.InboundSPI)
	xfrmState.Ifid = int(ifId)
	xfrmState.Auth = xfrmIntegrityAlgorithm
	xfrmState.Crypt = xfrmEncryptionAlgorithm
	xfrmState.ESN = childSA.NeedESN

	if err := netlink.XfrmStateAdd(xfrmState); err != nil {
		return fmt.Errorf("set XFRM state rule failed: %w", err)
	}

	xfrmPolicyTemplate := netlink.XfrmPolicyTmpl{
		Src:   xfrmState.Src,
		Dst:   xfrmState.Dst,
		Proto: xfrmState.Proto,
		Mode:  xfrmState.Mode,
		Spi:   xfrmState.Spi,
	}

	if childSA.SelectedIPProtocol == 0 {
		return errors.New("protocol == 0")
	}

	xfrmPolicy := new(netlink.XfrmPolicy)
	xfrmPolicy.Src = &childSA.TrafficSelectorRemote
	xfrmPolicy.Dst = &childSA.TrafficSelectorLocal
	xfrmPolicy.Proto = netlink.Proto(childSA.SelectedIPProtocol)
	xfrmPolicy.Dir = netlink.XFRM_DIR_IN
	xfrmPolicy.Ifid = int(ifId)
	xfrmPolicy.Tmpls = []netlink.XfrmPolicyTmpl{xfrmPolicyTemplate}

	if err := netlink.XfrmPolicyAdd(xfrmPolicy); err != nil {
		return fmt.Errorf("set XFRM policy rule failed: %w", err)
	}

	if ueIsInitiator {
		xfrmEncryptionAlgorithm.Key = childSA.InitiatorToResponderEncryptionKey
		if childSA.IntegTransformID != 0 {
			xfrmIntegrityAlgorithm.Key = childSA.InitiatorToResponderIntegrityKey
		}
	} else {
		xfrmEncryptionAlgorithm.Key = childSA.ResponderToInitiatorEncryptionKey
		if childSA.IntegTransformID != 0 {
			xfrmIntegrityAlgorithm.Key = childSA.ResponderToInitiatorIntegrityKey
		}
	}

	xfrmState.Src, xfrmState.Dst = xfrmState.Dst, xfrmState.Src
	xfrmState.Spi = int(childSA.OutboundSPI)

	if err := netlink.XfrmStateAdd(xfrmState); err != nil {
		return fmt.Errorf("set XFRM state rule failed: %w", err)
	}

	xfrmPolicyTemplate.Src, xfrmPolicyTemplate.Dst = xfrmPolicyTemplate.Dst, xfrmPolicyTemplate.Src
	xfrmPolicyTemplate.Spi = int(childSA.OutboundSPI)

	xfrmPolicy.Src, xfrmPolicy.Dst = xfrmPolicy.Dst, xfrmPolicy.Src
	xfrmPolicy.Dir = netlink.XFRM_DIR_OUT
	xfrmPolicy.Tmpls = []netlink.XfrmPolicyTmpl{xfrmPolicyTemplate}

	if err := netlink.XfrmPolicyAdd(xfrmPolicy); err != nil {
		return fmt.Errorf("set XFRM policy rule failed: %w", err)
	}
	return nil
}

// buildEAP5GANParametersTNGF builds the AN-Parameters TNGF's EAP-5G exchange carries.
// Unlike N3IWF's buildEAP5GANParameters (non3gpp.go), TNGF's also includes a UE
// Identity field (TS 24.502 Table 9.3.2.2.2.3-1 type 5) — ported from the reference
// test's tngfBuildEAP5GANParameters.
//
// mobileIdentityIei/mobileIdentityBuffer are the raw IEI byte and content bytes of
// the caller's 5GS mobile identity (SUCI). This takes them as plain bytes rather
// than a nas/ie.MobileId5GS, because that type no longer exposes a raw
// IEI/length/buffer view (nas v1.3.0 redesigned it into semantically-typed fields
// per identity kind) and this function only ever treated the identity as an
// opaque IEI+buffer pair for TNGF's AN-Parameter wire format anyway.
func buildEAP5GANParametersTNGF(mobileIdentityIei uint8, mobileIdentityBuffer []byte) []byte {
	var anParameters []byte

	// GUAMI. PLMN part matches PLMN_OCT; AMF ID "\xca\xfe\x00" matches amfCfg.yaml's amfId.
	anParameter := make([]byte, 2)
	guami := make([]byte, 6)
	copy(guami[0:3], PLMN_OCT)
	guami[3] = 0xca
	guami[4] = 0xfe
	guami[5] = 0x0
	anParameter[0] = ike_message.ANParametersTypeGUAMI
	anParameter[1] = byte(len(guami))
	anParameter = append(anParameter, guami...)
	anParameters = append(anParameters, anParameter...)

	// Establishment Cause
	anParameter = make([]byte, 2)
	establishmentCause := []byte{ike_message.EstablishmentCauseMO_Signaling}
	anParameter[0] = ike_message.ANParametersTypeEstablishmentCause
	anParameter[1] = byte(len(establishmentCause))
	anParameter = append(anParameter, establishmentCause...)
	anParameters = append(anParameters, anParameter...)

	// PLMN ID
	anParameter = make([]byte, 2)
	plmnID := []byte(PLMN_OCT)
	anParameter[0] = ike_message.ANParametersTypeSelectedPLMNID
	anParameter[1] = byte(len(plmnID))
	anParameter = append(anParameter, plmnID...)
	anParameters = append(anParameters, anParameter...)

	// NSSAI: both slices this IT environment supports (see const.go SD/SD_2)
	anParameter = make([]byte, 2)
	var nssai []byte
	snssai := make([]byte, 5)
	snssai[0] = 4
	snssai[1] = SST
	copy(snssai[2:5], SD_OCT)
	nssai = append(nssai, snssai...)
	snssai = make([]byte, 5)
	snssai[0] = 4
	snssai[1] = SST
	copy(snssai[2:5], SD_2_OCT)
	nssai = append(nssai, snssai...)
	anParameter[0] = ike_message.ANParametersTypeRequestedNSSAI
	anParameter[1] = byte(len(nssai))
	anParameter = append(anParameter, nssai...)
	anParameters = append(anParameters, anParameter...)

	// UE Identity (TNGF-only)
	anParameter = make([]byte, 3)
	anParameter[0] = anParametersTypeUEIdentity
	anParameter[1] = byte(16)
	anParameter[2] = mobileIdentityIei
	anParameterLength := make([]byte, 2)
	binary.BigEndian.PutUint16(anParameterLength, uint16(len(mobileIdentityBuffer)))
	anParameter = append(anParameter, anParameterLength...)
	anParameter = append(anParameter, mobileIdentityBuffer...)
	anParameters = append(anParameters, anParameter...)

	return anParameters
}
