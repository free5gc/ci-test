package test

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"reflect"

	"github.com/free5gc/nas"
	"github.com/free5gc/nas/logger"
	"github.com/free5gc/nas/nasConvert"
	"github.com/free5gc/nas/nasMessage"
	"github.com/free5gc/nas/nasType"
	"github.com/free5gc/nas/security"
	"github.com/free5gc/ngap/ngapType"
	"github.com/free5gc/openapi/models"
)

func NASDecode(ue *RanUeContext, securityHeaderType uint8, payload []byte) (msg *nas.Message, err error) {
	if ue == nil {
		err = fmt.Errorf("amfUe is nil")
		return
	}
	if payload == nil {
		err = fmt.Errorf("Nas payload is empty")
		return
	}

	msg = new(nas.Message)
	msg.SecurityHeaderType = uint8(nas.GetSecurityHeaderType(payload) & 0x0f)
	if securityHeaderType == nas.SecurityHeaderTypePlainNas {
		err = msg.PlainNasDecode(&payload)
		return
	} else if ue.IntegrityAlg == security.AlgIntegrity128NIA0 {
		fmt.Println("decode payload is ", payload)
		// remove header
		payload = payload[3:]
		if err = security.NASEncrypt(ue.CipheringAlg, ue.KnasEnc, ue.DLCount.Get(), ue.GetBearerType(),
			security.DirectionDownlink, payload); err != nil {
			return nil, err
		}

		err = msg.PlainNasDecode(&payload)
		return
	} else { // Security protected NAS message
		securityHeader := payload[0:6]
		sequenceNumber := payload[6]
		receivedMac32 := securityHeader[2:]
		// remove security Header except for sequece Number
		payload = payload[6:]

		// a security protected NAS message must be integrity protected, and ciphering is optional
		ciphered := false
		switch msg.SecurityHeaderType {
		case nas.SecurityHeaderTypeIntegrityProtected:
			// fmt.Println("Security header type: Integrity Protected")
		case nas.SecurityHeaderTypeIntegrityProtectedAndCiphered:
			// fmt.Println("Security header type: Integrity Protected And Ciphered")
			ciphered = true
		case nas.SecurityHeaderTypeIntegrityProtectedWithNew5gNasSecurityContext:
			// fmt.Println("Security Header Type Integrity Protected With New 5g Nas Security Context")
			ue.DLCount.Set(0, 0)
		case nas.SecurityHeaderTypeIntegrityProtectedAndCipheredWithNew5gNasSecurityContext:
			// fmt.Println("Security header type: Integrity Protected And Ciphered With New 5G Security Context")
			ciphered = true
			ue.DLCount.Set(0, 0)
		default:
			return nil, fmt.Errorf("Wrong security header type: 0x%0x", msg.SecurityHeader.SecurityHeaderType)
		}
		// Caculate ul count
		if ue.DLCount.SQN() > sequenceNumber {
			ue.DLCount.SetOverflow(ue.DLCount.Overflow() + 1)
		}
		ue.DLCount.SetSQN(sequenceNumber)

		mac32, errNas := security.NASMacCalculate(ue.IntegrityAlg, ue.KnasInt, ue.DLCount.Get(), ue.GetBearerType(),
			security.DirectionDownlink, payload)
		if errNas != nil {
			return nil, errNas
		}
		if !reflect.DeepEqual(mac32, receivedMac32) {
			fmt.Printf("NAS MAC verification failed(0x%x != 0x%x)", mac32, receivedMac32)
		} else {
			// fmt.Printf("cmac value: 0x%x\n", mac32)
		}

		// remove sequece Number
		payload = payload[1:]
		if ciphered {
			if err = security.NASEncrypt(ue.CipheringAlg, ue.KnasEnc, ue.DLCount.Get(), ue.GetBearerType(),
				security.DirectionDownlink, payload); err != nil {
				return nil, err
			}
		}

		if err := msg.PlainNasDecode(&payload); err != nil {
			fmt.Println("nas decode err", err)
		}
		return msg, err
	}
}

func NASEncode(ue *RanUeContext, msg *nas.Message, securityContextAvailable bool, newSecurityContext bool) (
	payload []byte, err error) {
	var sequenceNumber uint8
	if ue == nil {
		err = fmt.Errorf("amfUe is nil")
		return
	}
	if msg == nil {
		err = fmt.Errorf("Nas Message is empty")
		return
	}

	if !securityContextAvailable {
		return msg.PlainNasEncode()
	} else {
		if newSecurityContext {
			ue.ULCount.Set(0, 0)
			ue.DLCount.Set(0, 0)
		}

		sequenceNumber = ue.ULCount.SQN()
		payload, err = msg.PlainNasEncode()
		if err != nil {
			return
		}
		if msg.SecurityHeader.SecurityHeaderType != nas.SecurityHeaderTypeIntegrityProtected &&
			msg.SecurityHeader.SecurityHeaderType != nas.SecurityHeaderTypePlainNas {
			if err = security.NASEncrypt(ue.CipheringAlg, ue.KnasEnc, ue.ULCount.Get(), ue.GetBearerType(),
				security.DirectionUplink, payload); err != nil {
				return
			}
		}
		// add sequece number
		payload = append([]byte{sequenceNumber}, payload[:]...)
		mac32 := make([]byte, 4)
		_ = mac32
		// fmt.Println("sequenceNumber", sequenceNumber)
		// fmt.Println("ue.IntegrityAlg", ue.IntegrityAlg)
		// fmt.Println("ue.KnasInt", ue.KnasInt)
		// fmt.Println("ue.ULCount.Get()", ue.ULCount.Get())
		// fmt.Println("security.Bearer3GPP", security.Bearer3GPP)
		// fmt.Println("security.DirectionUplink", security.DirectionUplink)
		// fmt.Println("payload", payload)

		mac32, err = security.NASMacCalculate(ue.IntegrityAlg, ue.KnasInt, ue.ULCount.Get(), ue.GetBearerType(),
			security.DirectionUplink, payload)
		if err != nil {
			return
		}

		// Add mac value
		payload = append(mac32, payload[:]...)
		// Add EPD and Security Type
		msgSecurityHeader := []byte{msg.SecurityHeader.ProtocolDiscriminator, msg.SecurityHeader.SecurityHeaderType}
		payload = append(msgSecurityHeader, payload[:]...)

		// Increase UL Count
		ue.ULCount.AddOne()
	}
	return payload, err
}

func EncodeNasPduWithSecurity(ue *RanUeContext, pdu []byte, securityHeaderType uint8,
	securityContextAvailable, newSecurityContext bool) ([]byte, error) {
	m := nas.NewMessage()
	err := m.PlainNasDecode(&pdu)
	if err != nil {
		return nil, err
	}
	m.SecurityHeader = nas.SecurityHeader{
		ProtocolDiscriminator: nasMessage.Epd5GSMobilityManagementMessage,
		SecurityHeaderType:    securityHeaderType,
	}
	return NASEncode(ue, m, securityContextAvailable, newSecurityContext)

}

func GetNasPdu(ue *RanUeContext, msg *ngapType.DownlinkNASTransport) (m *nas.Message) {
	for _, ie := range msg.ProtocolIEs.List {
		if ie.Id.Value == ngapType.ProtocolIEIDNASPDU {
			pkg := []byte(ie.Value.NASPDU.Value)
			m, err := NASDecode(ue, nas.GetSecurityHeaderType(pkg), pkg)
			if err != nil {
				return nil
			}
			return m
		}
	}
	return nil
}

func GetRegistrationRequest(
	registrationType uint8,
	mobileIdentity nasType.MobileIdentity5GS,
	requestedNSSAI *nasType.RequestedNSSAI,
	ueSecurityCapability *nasType.UESecurityCapability,
	capability5GMM *nasType.Capability5GMM,
	nasMessageContainer []uint8,
	uplinkDataStatus *nasType.UplinkDataStatus,
) []byte {
	m := nas.NewMessage()
	m.GmmMessage = nas.NewGmmMessage()
	m.GmmHeader.SetMessageType(nas.MsgTypeRegistrationRequest)

	registrationRequest := nasMessage.NewRegistrationRequest(0)
	registrationRequest.SetExtendedProtocolDiscriminator(nasMessage.Epd5GSMobilityManagementMessage)
	registrationRequest.SpareHalfOctetAndSecurityHeaderType.SetSecurityHeaderType(nas.SecurityHeaderTypePlainNas)
	registrationRequest.SpareHalfOctetAndSecurityHeaderType.SetSpareHalfOctet(0x00)
	registrationRequest.RegistrationRequestMessageIdentity.SetMessageType(nas.MsgTypeRegistrationRequest)
	registrationRequest.NgksiAndRegistrationType5GS.SetTSC(nasMessage.TypeOfSecurityContextFlagNative)
	registrationRequest.NgksiAndRegistrationType5GS.SetNasKeySetIdentifiler(0x7)
	registrationRequest.NgksiAndRegistrationType5GS.SetFOR(1)
	registrationRequest.NgksiAndRegistrationType5GS.SetRegistrationType5GS(registrationType)
	registrationRequest.MobileIdentity5GS = mobileIdentity

	registrationRequest.UESecurityCapability = ueSecurityCapability
	registrationRequest.Capability5GMM = capability5GMM
	registrationRequest.RequestedNSSAI = requestedNSSAI
	registrationRequest.UplinkDataStatus = uplinkDataStatus

	if nasMessageContainer != nil {
		registrationRequest.NASMessageContainer = nasType.NewNASMessageContainer(
			nasMessage.RegistrationRequestNASMessageContainerType)
		registrationRequest.NASMessageContainer.SetLen(uint16(len(nasMessageContainer)))
		registrationRequest.NASMessageContainer.SetNASMessageContainerContents(nasMessageContainer)
	}

	m.GmmMessage.RegistrationRequest = registrationRequest

	data := new(bytes.Buffer)
	err := m.GmmMessageEncode(data)
	if err != nil {
		fmt.Println(err.Error())
	}

	return data.Bytes()
}

func GetAuthenticationResponse(authenticationResponseParam []uint8, eapMsg string) []byte {

	m := nas.NewMessage()
	m.GmmMessage = nas.NewGmmMessage()
	m.GmmHeader.SetMessageType(nas.MsgTypeAuthenticationResponse)

	authenticationResponse := nasMessage.NewAuthenticationResponse(0)
	authenticationResponse.ExtendedProtocolDiscriminator.SetExtendedProtocolDiscriminator(
		nasMessage.Epd5GSMobilityManagementMessage)
	authenticationResponse.SpareHalfOctetAndSecurityHeaderType.SetSecurityHeaderType(nas.SecurityHeaderTypePlainNas)
	authenticationResponse.SpareHalfOctetAndSecurityHeaderType.SetSpareHalfOctet(0)
	authenticationResponse.AuthenticationResponseMessageIdentity.SetMessageType(nas.MsgTypeAuthenticationResponse)

	if len(authenticationResponseParam) > 0 {
		authenticationResponse.AuthenticationResponseParameter = nasType.NewAuthenticationResponseParameter(
			nasMessage.AuthenticationResponseAuthenticationResponseParameterType)
		authenticationResponse.AuthenticationResponseParameter.SetLen(uint8(len(authenticationResponseParam)))
		copy(authenticationResponse.AuthenticationResponseParameter.Octet[:], authenticationResponseParam[0:16])
	} else if eapMsg != "" {
		rawEapMsg, err := base64.StdEncoding.DecodeString(eapMsg)
		if err != nil {
			logger.NasMsgLog.Warnf("EAP decode error: %+v", err)
		}
		authenticationResponse.EAPMessage = nasType.NewEAPMessage(nasMessage.AuthenticationResponseEAPMessageType)
		authenticationResponse.EAPMessage.SetLen(uint16(len(rawEapMsg)))
		authenticationResponse.EAPMessage.SetEAPMessage(rawEapMsg)
	}

	m.GmmMessage.AuthenticationResponse = authenticationResponse

	data := new(bytes.Buffer)
	err := m.GmmMessageEncode(data)
	if err != nil {
		fmt.Println(err.Error())
	}

	return data.Bytes()
}

func GetSecurityModeComplete(nasMessageContainer []uint8) []byte {

	m := nas.NewMessage()
	m.GmmMessage = nas.NewGmmMessage()
	m.GmmHeader.SetMessageType(nas.MsgTypeSecurityModeComplete)

	securityModeComplete := nasMessage.NewSecurityModeComplete(0)
	securityModeComplete.ExtendedProtocolDiscriminator.SetExtendedProtocolDiscriminator(
		nasMessage.Epd5GSMobilityManagementMessage)
	// TODO: modify security header type if need security protected
	securityModeComplete.SpareHalfOctetAndSecurityHeaderType.SetSecurityHeaderType(nas.SecurityHeaderTypePlainNas)
	securityModeComplete.SpareHalfOctetAndSecurityHeaderType.SetSpareHalfOctet(0)
	securityModeComplete.SecurityModeCompleteMessageIdentity.SetMessageType(nas.MsgTypeSecurityModeComplete)

	securityModeComplete.IMEISV = nasType.NewIMEISV(nasMessage.SecurityModeCompleteIMEISVType)
	securityModeComplete.IMEISV.SetLen(9)
	securityModeComplete.SetOddEvenIdic(0)
	securityModeComplete.SetTypeOfIdentity(nasMessage.MobileIdentity5GSTypeImeisv)
	securityModeComplete.SetIdentityDigit1(1)
	securityModeComplete.SetIdentityDigitP_1(1)
	securityModeComplete.SetIdentityDigitP(1)

	if nasMessageContainer != nil {
		securityModeComplete.NASMessageContainer = nasType.NewNASMessageContainer(
			nasMessage.SecurityModeCompleteNASMessageContainerType)
		securityModeComplete.NASMessageContainer.SetLen(uint16(len(nasMessageContainer)))
		securityModeComplete.NASMessageContainer.SetNASMessageContainerContents(nasMessageContainer)
	}

	m.GmmMessage.SecurityModeComplete = securityModeComplete

	data := new(bytes.Buffer)
	err := m.GmmMessageEncode(data)
	if err != nil {
		fmt.Println(err.Error())
	}

	return data.Bytes()
}

func GetRegistrationComplete(sorTransparentContainer []uint8) []byte {
	m := nas.NewMessage()
	m.GmmMessage = nas.NewGmmMessage()
	m.GmmHeader.SetMessageType(nas.MsgTypeRegistrationComplete)

	registrationComplete := nasMessage.NewRegistrationComplete(0)
	registrationComplete.ExtendedProtocolDiscriminator.SetExtendedProtocolDiscriminator(
		nasMessage.Epd5GSMobilityManagementMessage)
	registrationComplete.SpareHalfOctetAndSecurityHeaderType.SetSecurityHeaderType(nas.SecurityHeaderTypePlainNas)
	registrationComplete.SpareHalfOctetAndSecurityHeaderType.SetSpareHalfOctet(0)
	registrationComplete.RegistrationCompleteMessageIdentity.SetMessageType(nas.MsgTypeRegistrationComplete)

	if sorTransparentContainer != nil {
		registrationComplete.SORTransparentContainer = nasType.NewSORTransparentContainer(
			nasMessage.RegistrationCompleteSORTransparentContainerType)
		registrationComplete.SORTransparentContainer.SetLen(uint16(len(sorTransparentContainer)))
		registrationComplete.SORTransparentContainer.SetSORContent(sorTransparentContainer)
	}

	m.GmmMessage.RegistrationComplete = registrationComplete

	data := new(bytes.Buffer)
	err := m.GmmMessageEncode(data)
	if err != nil {
		fmt.Println(err.Error())
	}

	return data.Bytes()
}

func GetPduSessionEstablishmentRequest(pduSessionId uint8) []byte {

	m := nas.NewMessage()
	m.GsmMessage = nas.NewGsmMessage()
	m.GsmHeader.SetMessageType(nas.MsgTypePDUSessionEstablishmentRequest)

	pduSessionEstablishmentRequest := nasMessage.NewPDUSessionEstablishmentRequest(0)
	pduSessionEstablishmentRequest.ExtendedProtocolDiscriminator.SetExtendedProtocolDiscriminator(
		nasMessage.Epd5GSSessionManagementMessage)
	pduSessionEstablishmentRequest.SetMessageType(nas.MsgTypePDUSessionEstablishmentRequest)
	pduSessionEstablishmentRequest.PDUSessionID.SetPDUSessionID(pduSessionId)
	pduSessionEstablishmentRequest.PTI.SetPTI(0x00)
	pduSessionEstablishmentRequest.IntegrityProtectionMaximumDataRate.
		SetMaximumDataRatePerUEForUserPlaneIntegrityProtectionForDownLink(0xff)
	pduSessionEstablishmentRequest.IntegrityProtectionMaximumDataRate.
		SetMaximumDataRatePerUEForUserPlaneIntegrityProtectionForUpLink(0xff)

	pduSessionEstablishmentRequest.PDUSessionType =
		nasType.NewPDUSessionType(nasMessage.PDUSessionEstablishmentRequestPDUSessionTypeType)
	pduSessionEstablishmentRequest.PDUSessionType.SetPDUSessionTypeValue(uint8(0x01)) //IPv4 type

	pduSessionEstablishmentRequest.SSCMode =
		nasType.NewSSCMode(nasMessage.PDUSessionEstablishmentRequestSSCModeType)
	pduSessionEstablishmentRequest.SSCMode.SetSSCMode(uint8(0x01)) //SSC Mode 1

	pduSessionEstablishmentRequest.ExtendedProtocolConfigurationOptions =
		nasType.NewExtendedProtocolConfigurationOptions(
			nasMessage.PDUSessionEstablishmentRequestExtendedProtocolConfigurationOptionsType)
	protocolConfigurationOptions := nasConvert.NewProtocolConfigurationOptions()
	protocolConfigurationOptions.AddIPAddressAllocationViaNASSignallingUL()
	protocolConfigurationOptions.AddDNSServerIPv4AddressRequest()
	protocolConfigurationOptions.AddDNSServerIPv6AddressRequest()
	pcoContents := protocolConfigurationOptions.Marshal()
	pcoContentsLength := len(pcoContents)
	pduSessionEstablishmentRequest.ExtendedProtocolConfigurationOptions.SetLen(uint16(pcoContentsLength))
	pduSessionEstablishmentRequest.ExtendedProtocolConfigurationOptions.
		SetExtendedProtocolConfigurationOptionsContents(pcoContents)

	m.GsmMessage.PDUSessionEstablishmentRequest = pduSessionEstablishmentRequest

	data := new(bytes.Buffer)
	err := m.GsmMessageEncode(data)
	if err != nil {
		fmt.Println(err.Error())
	}

	return data.Bytes()
}

func GetUlNasTransport_PduSessionEstablishmentRequest(pduSessionId uint8, requestType uint8, dnnString string,
	sNssai *models.Snssai) []byte {

	pduSessionEstablishmentRequest := GetPduSessionEstablishmentRequest(pduSessionId)

	m := nas.NewMessage()
	m.GmmMessage = nas.NewGmmMessage()
	m.GmmHeader.SetMessageType(nas.MsgTypeULNASTransport)

	ulNasTransport := nasMessage.NewULNASTransport(0)
	ulNasTransport.SpareHalfOctetAndSecurityHeaderType.SetSecurityHeaderType(nas.SecurityHeaderTypePlainNas)
	ulNasTransport.SetMessageType(nas.MsgTypeULNASTransport)
	ulNasTransport.ExtendedProtocolDiscriminator.SetExtendedProtocolDiscriminator(
		nasMessage.Epd5GSMobilityManagementMessage)
	ulNasTransport.PduSessionID2Value = new(nasType.PduSessionID2Value)
	ulNasTransport.PduSessionID2Value.SetIei(nasMessage.ULNASTransportPduSessionID2ValueType)
	ulNasTransport.PduSessionID2Value.SetPduSessionID2Value(pduSessionId)
	ulNasTransport.RequestType = new(nasType.RequestType)
	ulNasTransport.RequestType.SetIei(nasMessage.ULNASTransportRequestTypeType)
	ulNasTransport.RequestType.SetRequestTypeValue(requestType)
	if dnnString != "" {
		ulNasTransport.DNN = new(nasType.DNN)
		ulNasTransport.DNN.SetIei(nasMessage.ULNASTransportDNNType)
		ulNasTransport.DNN.SetDNN(dnnString)
	}
	if sNssai != nil {
		var sdTemp [3]uint8
		sd, err := hex.DecodeString(sNssai.Sd)
		if err != nil {
			logger.NasMsgLog.Errorf("sNssai decode error: %+v", err)
		}
		copy(sdTemp[:], sd)
		ulNasTransport.SNSSAI = nasType.NewSNSSAI(nasMessage.ULNASTransportSNSSAIType)
		ulNasTransport.SNSSAI.SetLen(4)
		ulNasTransport.SNSSAI.SetSST(uint8(sNssai.Sst))
		ulNasTransport.SNSSAI.SetSD(sdTemp)
	}

	ulNasTransport.SpareHalfOctetAndPayloadContainerType.SetPayloadContainerType(nasMessage.PayloadContainerTypeN1SMInfo)
	ulNasTransport.PayloadContainer.SetLen(uint16(len(pduSessionEstablishmentRequest)))
	ulNasTransport.PayloadContainer.SetPayloadContainerContents(pduSessionEstablishmentRequest)

	m.GmmMessage.ULNASTransport = ulNasTransport

	data := new(bytes.Buffer)
	err := m.GmmMessageEncode(data)
	if err != nil {
		fmt.Println(err.Error())
	}

	return data.Bytes()
}
