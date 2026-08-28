package test

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"

	"test/consumerTestdata/UDR/TestRegistrationProcedure"

	"github.com/calee0219/fatal"
	"golang.org/x/net/ipv4"

	"github.com/free5gc/nas/ie"
	"github.com/free5gc/nas/message"
	"github.com/free5gc/openapi/models"
	"github.com/free5gc/util/milenage"
	"github.com/free5gc/util/ueauth"
	"github.com/free5gc/webconsole/backend/WebUI"
)

type RanUeContext struct {
	Supi               string
	RanUeNgapId        int64
	AmfUeNgapId        int64
	ULCount            message.Count
	DLCount            message.Count
	CipheringAlg       ie.AlgCiphering
	IntegrityAlg       ie.AlgIntegrity
	KnasEnc            [16]uint8
	KnasInt            [16]uint8
	Kamf               []uint8
	AnType             models.AccessType
	AuthenticationSubs models.Udr_DR_AuthenticationSubscription
}

func CalculateIpv4HeaderChecksum(hdr *ipv4.Header) uint32 {
	var Checksum uint32
	Checksum += uint32((hdr.Version<<4|(20>>2&0x0f))<<8 | hdr.TOS)
	Checksum += uint32(hdr.TotalLen)
	Checksum += uint32(hdr.ID)
	Checksum += uint32((hdr.FragOff & 0x1fff) | (int(hdr.Flags) << 13))
	Checksum += uint32((hdr.TTL << 8) | (hdr.Protocol))

	src := hdr.Src.To4()
	Checksum += uint32(src[0])<<8 | uint32(src[1])
	Checksum += uint32(src[2])<<8 | uint32(src[3])
	dst := hdr.Dst.To4()
	Checksum += uint32(dst[0])<<8 | uint32(dst[1])
	Checksum += uint32(dst[2])<<8 | uint32(dst[3])
	return ^(Checksum&0xffff0000>>16 + Checksum&0xffff)
}

func GetAuthSubscription(k, opc, op string) models.Udr_DR_AuthenticationSubscription {
	var authSubs models.Udr_DR_AuthenticationSubscription
	authSubs.EncPermanentKey = k
	authSubs.EncOpcKey = opc
	authSubs.AuthenticationManagementField = "8000"

	authSubs.SequenceNumber = &models.Udr_DR_SequenceNumber{
		Sqn: UE_SQN,
	}
	authSubs.AuthenticationMethod = models.Udr_DR_AuthMethod_5_G_AKA
	return authSubs
}

func GetEAPAKAPrimeAuthSubscription(k, opc string) models.Udr_DR_AuthenticationSubscription {
	var authSubs models.Udr_DR_AuthenticationSubscription
	authSubs.EncPermanentKey = k
	authSubs.EncOpcKey = opc
	authSubs.AuthenticationManagementField = "8000"
	authSubs.SequenceNumber = &models.Udr_DR_SequenceNumber{
		Sqn: UE_SQN,
	}
	authSubs.AuthenticationMethod = models.Udr_DR_AuthMethod_EAP_AKA_PRIME
	return authSubs
}

func GetAccessAndMobilitySubscriptionData() (amData models.Udr_DR_AccessAndMobilitySubscriptionData) {
	return TestRegistrationProcedure.TestAmDataTable[TestRegistrationProcedure.FREE5GC_CASE]
}

func GetSmfSelectionSubscriptionData() (smfSelData models.Udr_DR_SmfSelectionSubscriptionData) {
	return TestRegistrationProcedure.TestSmfSelDataTable[TestRegistrationProcedure.FREE5GC_CASE]
}

func GetSessionManagementSubscriptionData() (smfSelData []models.Udm_SDM_SessionManagementSubscriptionData) {
	return TestRegistrationProcedure.TestSmSelDataTable[TestRegistrationProcedure.FREE5GC_CASE]
}

func GetAmPolicyData() (amPolicyData models.Udr_DR_AmPolicyData) {
	return TestRegistrationProcedure.TestAmPolicyDataTable[TestRegistrationProcedure.FREE5GC_CASE]
}

func GetSmPolicyData() (smPolicyData models.Udr_DR_SmPolicyData) {
	return TestRegistrationProcedure.TestSmPolicyDataTable[TestRegistrationProcedure.FREE5GC_CASE]
}

func GetChargingData() (chargingDatas []WebUI.ChargingData) {
	return TestRegistrationProcedure.TestChargingDataTable[TestRegistrationProcedure.FREE5GC_CASE]
}

func GetFlowRuleData() (flowRules []WebUI.FlowRule) {
	return TestRegistrationProcedure.TestFlowRuleTable[TestRegistrationProcedure.FREE5GC_CASE]
}

func GetQosFlowData() (qosFlows []WebUI.QosFlow) {
	return TestRegistrationProcedure.TestQoSFlowTable[TestRegistrationProcedure.FREE5GC_CASE]
}

func NewRanUeContext(supi string, ranUeNgapId int64, cipheringAlg ie.AlgCiphering,
	integrityAlg ie.AlgIntegrity, AnType models.AccessType,
) *RanUeContext {
	ue := RanUeContext{}
	ue.RanUeNgapId = ranUeNgapId
	ue.Supi = supi
	ue.CipheringAlg = cipheringAlg
	ue.IntegrityAlg = integrityAlg
	ue.AnType = AnType
	return &ue
}

func (ue *RanUeContext) DeriveRESstarAndSetKey(
	authSubs models.Udr_DR_AuthenticationSubscription, rand []byte, snName string,
) []byte {
	sqn, err := hex.DecodeString(authSubs.SequenceNumber.Sqn)
	if err != nil {
		fatal.Fatalf("DecodeString error: %+v", err)
	}

	amf, err := hex.DecodeString(authSubs.AuthenticationManagementField)
	if err != nil {
		fatal.Fatalf("DecodeString error: %+v", err)
	}

	// Run milenage
	opc := make([]byte, 16)
	k, err := hex.DecodeString(authSubs.EncPermanentKey)
	if err != nil {
		fatal.Fatalf("DecodeString error: %+v", err)
	}

	if authSubs.EncOpcKey == "" {
		fatal.Fatalf("%+v", errors.New("EncOpcKey is empty"))
	} else {
		opc, err = hex.DecodeString(authSubs.EncOpcKey)
		if err != nil {
			fatal.Fatalf("DecodeString error: %+v", err)
		}
	}

	// Run milenage
	ik, ck, res, autn, err := milenage.GenerateAKAParameters(opc, k, rand, sqn, amf)
	if err != nil {
		fatal.Fatalf("GenerateAKAParameters error: %+v", err)
	}

	ak := make([]byte, len(sqn))
	for i := 0; i < len(sqn); i++ {
		ak[i] = sqn[i] ^ autn[i]
	}

	// derive RES*
	key := append(ck, ik...)
	FC := ueauth.FC_FOR_RES_STAR_XRES_STAR_DERIVATION
	P0 := []byte(snName)
	P1 := rand
	P2 := res

	ue.DerivateKamf(key, snName, sqn, ak)
	ue.DerivateAlgKey()
	kdfVal_for_resStar, err :=
		ueauth.GetKDFValue(key, FC, P0, ueauth.KDFLen(P0), P1, ueauth.KDFLen(P1), P2, ueauth.KDFLen(P2))
	if err != nil {
		fatal.Fatalf("GetKDFValue error: %+v", err)
	}
	return kdfVal_for_resStar[len(kdfVal_for_resStar)/2:]
}

func (ue *RanUeContext) DeriveResEAPMessageAndSetKey(
	authSubs models.Udr_DR_AuthenticationSubscription, eAPMessage []byte, snName string,
) []byte {
	sqn, err := hex.DecodeString(authSubs.SequenceNumber.Sqn)
	if err != nil {
		fatal.Fatalf("DecodeString error: %+v", err)
	}

	var attrLen int
	var rand []byte
	var autn []byte
	data := eAPMessage[5:]
	dataLen := len(data)
	for i := 3; i < dataLen; i += attrLen {
		attrType := data[i]
		attrLen = int(data[i+1]) * 4
		if attrLen == 0 {
			fatal.Fatalf("Decode EAP packet error: %+v", fmt.Errorf("attribute length equal to zero"))
		}
		if i+attrLen > dataLen {
			fatal.Fatalf("Decode EAP packet error: %+v", fmt.Errorf("packet length out of range"))
		}
		if attrType == 1 { // AT_RAND
			rand = data[i+4 : i+20]
		} else if attrType == 2 { // AT_AUTN
			autn = data[i+4 : i+20]
		}
	}
	if len(rand) == 0 || len(autn) == 0 {
		fatal.Fatalf("Decode EAP packet error: %+v", fmt.Errorf("Length of RAND or AUTN is zero"))
	}

	amf, err := hex.DecodeString(authSubs.AuthenticationManagementField)
	if err != nil {
		fatal.Fatalf("DecodeString error: %+v", err)
	}

	// Run milenage
	opc := make([]byte, 16)
	k, err := hex.DecodeString(authSubs.EncPermanentKey)
	if err != nil {
		fatal.Fatalf("DecodeString error: %+v", err)
	}

	if authSubs.EncOpcKey == "" {
		fatal.Fatalf("%+v", errors.New("EncOpcKey is empty"))
	} else {
		opc, err = hex.DecodeString(authSubs.EncOpcKey)
		if err != nil {
			fatal.Fatalf("DecodeString error: %+v", err)
		}
	}

	// Run milenage
	ik, ck, res, _, err := milenage.GenerateAKAParameters(opc, k, rand, sqn, amf)
	if err != nil {
		fatal.Fatalf("GenerateAKAParameters error: %+v", err)
	}

	// derive CK' IK'
	key := append(ck, ik...)
	FC := ueauth.FC_FOR_CK_PRIME_IK_PRIME_DERIVATION
	P0 := []byte(snName)
	P1 := autn[:6]
	kdfVal, err := ueauth.GetKDFValue(key, FC, P0, ueauth.KDFLen(P0), P1, ueauth.KDFLen(P1))
	if err != nil {
		fatal.Fatalf("GetKDFValue error: %+v", err)
	}
	ckPrime := kdfVal[:len(kdfVal)/2]
	ikPrime := kdfVal[len(kdfVal)/2:]

	// derive Kaut Kausf Kseaf
	key = append(ikPrime, ckPrime...)
	// omit "imsi-" part in supi
	sBase := []byte("EAP-AKA'" + ue.Supi[5:])
	var MK, prev []byte
	prfRounds := 208/32 + 1
	for i := 0; i < prfRounds; i++ {
		// Create a new HMAC by defining the hash type and the key (as byte array)
		h := hmac.New(sha256.New, key)

		hexNum := (byte)(i + 1)
		ap := append(sBase, hexNum)
		s := append(prev, ap...)

		// Write Data to it
		if _, err1 := h.Write(s); err1 != nil {
			fatal.Fatalf("EAP-AKA' prf error: %+v", err1)
		}

		// Get result
		sha := h.Sum(nil)
		MK = append(MK, sha...)
		prev = sha
	}
	Kaut := MK[16:48]
	Kausf := MK[144:176]
	P0 = []byte(snName)
	Kseaf, err := ueauth.GetKDFValue(Kausf, ueauth.FC_FOR_KSEAF_DERIVATION, P0, ueauth.KDFLen(P0))
	if err != nil {
		fatal.Fatalf("GetKDFValue error: %+v", err)
	}

	// fill response EAP packet
	resEAPMessage := make([]byte, 40)
	copy(resEAPMessage, eAPMessage[:8])
	resEAPMessage[0] = 2
	resEAPMessage[2] = 0
	resEAPMessage[3] = 40
	resEAPMessage[8] = 3 // AT_RES
	resEAPMessage[9] = 3
	resEAPMessage[11] = 64
	copy(resEAPMessage[12:20], res[:])
	resEAPMessage[20] = 11 // AT_MAC
	resEAPMessage[21] = 5

	// calculate MAC
	h := hmac.New(sha256.New, Kaut)
	if _, err2 := h.Write(resEAPMessage); err2 != nil {
		fatal.Fatalf("MAC calculate error: %+v", err2)
	}
	sum := h.Sum(nil)
	copy(resEAPMessage[24:], sum[:16])

	// derive Kamf
	supiRegexp, err := regexp.Compile("(?:imsi|supi)-([0-9]{5,15})")
	if err != nil {
		fatal.Fatalf("regexp Compile error: %+v", err)
	}
	groups := supiRegexp.FindStringSubmatch(ue.Supi)

	P0 = []byte(groups[1])
	L0 := ueauth.KDFLen(P0)
	P1 = []byte{0x00, 0x00}
	L1 := ueauth.KDFLen(P1)

	ue.Kamf, err = ueauth.GetKDFValue(Kseaf, ueauth.FC_FOR_KAMF_DERIVATION, P0, L0, P1, L1)
	if err != nil {
		fatal.Fatalf("GetKDFValue error: %+v", err)
	}

	ue.DerivateAlgKey()
	return resEAPMessage
}

func (ue *RanUeContext) DerivateKamf(key []byte, snName string, SQN, AK []byte) {
	FC := ueauth.FC_FOR_KAUSF_DERIVATION
	P0 := []byte(snName)
	SQNxorAK := make([]byte, 6)
	for i := 0; i < len(SQN); i++ {
		SQNxorAK[i] = SQN[i] ^ AK[i]
	}
	P1 := SQNxorAK
	Kausf, err := ueauth.GetKDFValue(key, FC, P0, ueauth.KDFLen(P0), P1, ueauth.KDFLen(P1))
	if err != nil {
		fatal.Fatalf("GetKDFValue error: %+v", err)
	}
	P0 = []byte(snName)
	Kseaf, err := ueauth.GetKDFValue(Kausf, ueauth.FC_FOR_KSEAF_DERIVATION, P0, ueauth.KDFLen(P0))
	if err != nil {
		fatal.Fatalf("GetKDFValue error: %+v", err)
	}

	supiRegexp, err := regexp.Compile("(?:imsi|supi)-([0-9]{5,15})")
	if err != nil {
		fatal.Fatalf("regexp Compile error: %+v", err)
	}
	groups := supiRegexp.FindStringSubmatch(ue.Supi)

	P0 = []byte(groups[1])
	L0 := ueauth.KDFLen(P0)
	P1 = []byte{0x00, 0x00}
	L1 := ueauth.KDFLen(P1)

	ue.Kamf, err = ueauth.GetKDFValue(Kseaf, ueauth.FC_FOR_KAMF_DERIVATION, P0, L0, P1, L1)
	if err != nil {
		fatal.Fatalf("GetKDFValue error: %+v", err)
	}
}

// Algorithm key Derivation function defined in TS 33.501 Annex A.9
func (ue *RanUeContext) DerivateAlgKey() {
	// Security Key
	P0 := []byte{message.NNASEncAlg}
	L0 := ueauth.KDFLen(P0)
	P1 := []byte{uint8(ue.CipheringAlg)}
	L1 := ueauth.KDFLen(P1)

	kenc, err := ueauth.GetKDFValue(ue.Kamf, ueauth.FC_FOR_ALGORITHM_KEY_DERIVATION, P0, L0, P1, L1)
	if err != nil {
		fatal.Fatalf("GetKDFValue error: %+v", err)
	}
	copy(ue.KnasEnc[:], kenc[16:32])

	// Integrity Key
	P0 = []byte{message.NNASIntAlg}
	L0 = ueauth.KDFLen(P0)
	P1 = []byte{uint8(ue.IntegrityAlg)}
	L1 = ueauth.KDFLen(P1)

	kint, err := ueauth.GetKDFValue(ue.Kamf, ueauth.FC_FOR_ALGORITHM_KEY_DERIVATION, P0, L0, P1, L1)
	if err != nil {
		fatal.Fatalf("GetKDFValue error: %+v", err)
	}
	copy(ue.KnasInt[:], kint[16:32])
}

func (ue *RanUeContext) GetUESecurityCapability() *ie.UESecCapability {
	// Length 2 keeps the two octets the old packet carried (EA then IA).
	capability := &ie.UESecCapability{Length: 2}

	switch ue.CipheringAlg {
	case message.AlgCiphering128NEA0:
		capability.EA05G = true
	case message.AlgCiphering128NEA1:
		capability.EA1_128_5G = true
	case message.AlgCiphering128NEA2:
		capability.EA2_128_5G = true
	case message.AlgCiphering128NEA3:
		capability.EA3_128_5G = true
	}

	switch ue.IntegrityAlg {
	case message.AlgIntegrity128NIA0:
		capability.IA05G = true
	case message.AlgIntegrity128NIA1:
		capability.IA1_128_5G = true
	case message.AlgIntegrity128NIA2:
		capability.IA2_128_5G = true
	case message.AlgIntegrity128NIA3:
		capability.IA3_128_5G = true
	}

	return capability
}

func (ue *RanUeContext) Get5GMMCapability() *ie.Capability5GMM {
	// The old packet set octet 3 to 0x07, i.e. bits 1-3: S1 mode, handover
	// attach and LPP.
	return &ie.Capability5GMM{
		Length:   1,
		S1Mode:   true,
		HOAttach: true,
		LPP:      true,
	}
}

func (ue *RanUeContext) GetBearerType() message.BearerType {
	if ue.AnType == models.AccessType_3_GPP_ACCESS {
		return message.Bearer3GPP
	} else if ue.AnType == models.AccessType_NON_3_GPP_ACCESS {
		return message.BearerNon3GPP
	} else {
		return message.OnlyOneBearer
	}
}
