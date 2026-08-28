package test

// RADIUS (RFC 2865) + EAP-over-RADIUS (RFC 3579) client, written directly against the
// wire format rather than depending on free5gc/tngf/pkg/radius/*: TNGF relays EAP-5G
// over RADIUS Access-Request/Access-Accept cycles (unlike N3IWF, which carries EAP-5G
// directly inside IKE_AUTH — see non3gpp.go), and pulling in the TNGF module just for
// its RADIUS message structs would create exactly the tight coupling to free5gc/tngf's
// source tree this IT suite avoids elsewhere. The EAP payload itself (Identity/Expanded)
// is marshaled with the already-vendored github.com/free5gc/ike/eap package, since that
// part of the wire format is identical to N3IWF's.

import (
	"crypto/hmac"
	"crypto/md5"
	"encoding/binary"
	"errors"

	eap "github.com/free5gc/ike/eap"
)

// RADIUS attribute types (RFC 2865 section 5, RFC 2869 section 5.14).
const (
	radiusAttrUserName             uint8 = 1
	radiusAttrCalledStationId      uint8 = 30
	radiusAttrCallingStationId     uint8 = 31
	radiusAttrEAPMessage           uint8 = 79
	radiusAttrMessageAuthenticator uint8 = 80
)

// RADIUS packet codes (RFC 2865 section 3).
const (
	RadiusCodeAccessRequest uint8 = 1
	RadiusCodeAccessAccept  uint8 = 2
	RadiusCodeAccessReject  uint8 = 3
)

// EAP-5G message-id type (TS 24.502 9.3.2.2.2.2). Only 5G-Notification is needed here;
// 5G-Start/5G-NAS/5G-Stop are already defined in github.com/free5gc/ike/message and
// reused directly.
const eap5GType5GNotification uint8 = 3

// AN-Parameter type for UE Identity (TS 24.502 Table 9.3.2.2.2.3-1). TNGF's AN-Parameters
// include this field; N3IWF's (see buildEAP5GANParameters in non3gpp.go) don't. TNGF's own
// type ordering (pkg/radius/message/types.go) reserves 5 for the unused "Selected NID" and
// puts UE Identity at 6 — github.com/free5gc/ike/message only defines through 4 (GUAMI=1,
// SelectedPLMNID=2, RequestedNSSAI=3, EstablishmentCause=4), so this one isn't reused from there.
const anParametersTypeUEIdentity uint8 = 6

type radiusAttribute struct {
	Type  uint8
	Value []byte
}

type RadiusMessage struct {
	Code       uint8
	Identifier uint8
	Auth       [16]byte
	Attributes []radiusAttribute
}

func (m *RadiusMessage) BuildRadiusHeader(code uint8, identifier uint8, auth []byte) {
	m.Code = code
	m.Identifier = identifier
	copy(m.Auth[:], auth)
}

func (m *RadiusMessage) addAttribute(t uint8, value []byte) {
	m.Attributes = append(m.Attributes, radiusAttribute{Type: t, Value: value})
}

// addEAPMessage splits the EAP payload across multiple EAP-Message attributes if it
// exceeds 253 bytes (the max RADIUS attribute value length), per RFC 3579 section 3.1.
func (m *RadiusMessage) addEAPMessage(eapPayload []byte) {
	if len(eapPayload) == 0 {
		m.addAttribute(radiusAttrEAPMessage, nil)
		return
	}
	for offset := 0; offset < len(eapPayload); offset += 253 {
		end := offset + 253
		if end > len(eapPayload) {
			end = len(eapPayload)
		}
		m.addAttribute(radiusAttrEAPMessage, eapPayload[offset:end])
	}
}

// getEAPMessage reassembles the (possibly multi-attribute) EAP-Message content.
func (m *RadiusMessage) getEAPMessage() []byte {
	var eapPayload []byte
	for _, attr := range m.Attributes {
		if attr.Type == radiusAttrEAPMessage {
			eapPayload = append(eapPayload, attr.Value...)
		}
	}
	return eapPayload
}

// Encode serializes the RADIUS packet (RFC 2865 section 3).
func (m *RadiusMessage) Encode() ([]byte, error) {
	buf := make([]byte, 20)
	buf[0] = m.Code
	buf[1] = m.Identifier
	copy(buf[4:20], m.Auth[:])

	for _, attr := range m.Attributes {
		if len(attr.Value) > 253 {
			return nil, errors.New("RadiusMessage encode: attribute value exceeds 253 bytes")
		}
		buf = append(buf, attr.Type, uint8(len(attr.Value)+2))
		buf = append(buf, attr.Value...)
	}

	if len(buf) > 65535 {
		return nil, errors.New("RadiusMessage encode: packet too large")
	}
	binary.BigEndian.PutUint16(buf[2:4], uint16(len(buf)))
	return buf, nil
}

// Decode parses a RADIUS packet (RFC 2865 section 3).
func (m *RadiusMessage) Decode(b []byte) error {
	if len(b) < 20 {
		return errors.New("RadiusMessage decode: packet too short")
	}
	m.Code = b[0]
	m.Identifier = b[1]
	length := binary.BigEndian.Uint16(b[2:4])
	if int(length) > len(b) {
		return errors.New("RadiusMessage decode: length field exceeds packet size")
	}
	copy(m.Auth[:], b[4:20])

	m.Attributes = nil
	offset := 20
	for offset < int(length) {
		if offset+2 > int(length) {
			return errors.New("RadiusMessage decode: truncated attribute header")
		}
		attrType := b[offset]
		attrLen := int(b[offset+1])
		if attrLen < 2 || offset+attrLen > int(length) {
			return errors.New("RadiusMessage decode: invalid attribute length")
		}
		m.Attributes = append(m.Attributes, radiusAttribute{
			Type:  attrType,
			Value: b[offset+2 : offset+attrLen],
		})
		offset += attrLen
	}
	return nil
}

// buildMessageAuthenticator computes the Message-Authenticator attribute value (RFC
// 2869 section 5.14): HMAC-MD5 over the whole packet, with the Message-Authenticator
// value itself zeroed, using the RADIUS shared secret.
func buildMessageAuthenticator(m *RadiusMessage, secret string) ([]byte, error) {
	zeroed := *m
	zeroed.Attributes = append([]radiusAttribute(nil), m.Attributes...)
	for i, attr := range zeroed.Attributes {
		if attr.Type == radiusAttrMessageAuthenticator {
			zeroed.Attributes[i].Value = make([]byte, 16)
		}
	}
	data, err := zeroed.Encode()
	if err != nil {
		return nil, err
	}
	h := hmac.New(md5.New, []byte(secret))
	if _, err := h.Write(data); err != nil {
		return nil, err
	}
	return h.Sum(nil), nil
}

// appendMessageAuthenticator adds a Message-Authenticator attribute and fills it in
// with the HMAC-MD5 computed over the resulting packet.
func appendMessageAuthenticator(m *RadiusMessage, secret string) error {
	m.addAttribute(radiusAttrMessageAuthenticator, make([]byte, 16))
	mac, err := buildMessageAuthenticator(m, secret)
	if err != nil {
		return err
	}
	m.Attributes[len(m.Attributes)-1].Value = mac
	return nil
}

// buildTngfAccessRequest builds an Access-Request carrying the given EAP payload plus
// the station-identifying attributes TNGF expects (values match tngfCfg.yaml's peer
// expectations, ported from the reference test).
func buildTngfAccessRequest(pktID uint8, auth []byte, eapPayload []byte) (*RadiusMessage, error) {
	m := new(RadiusMessage)
	m.BuildRadiusHeader(RadiusCodeAccessRequest, pktID, auth)
	m.addAttribute(radiusAttrUserName, []byte("tngfue"))
	m.addAttribute(radiusAttrCalledStationId, []byte("D4-6E-0E-65-AC-A2:free5gc-ap"))
	m.addAttribute(radiusAttrCallingStationId, []byte("C4-85-08-77-A7-D1"))
	m.addEAPMessage(eapPayload)
	if err := appendMessageAuthenticator(m, TNGF_RADIUS_SECRET); err != nil {
		return nil, err
	}
	return m, nil
}

func marshalEAPIdentity(identifier uint8, identity []byte) ([]byte, error) {
	e := &eap.EAP{
		Code:        eap.EapCodeResponse,
		Identifier:  identifier,
		EapTypeData: &eap.EapIdentity{IdentityData: identity},
	}
	return e.Marshal()
}

func marshalEAP5GNAS(identifier uint8, vendorData []byte) ([]byte, error) {
	e := &eap.EAP{
		Code:       eap.EapCodeResponse,
		Identifier: identifier,
		EapTypeData: &eap.EapExpanded{
			VendorID:   eap.VendorId3GPP,
			VendorType: eap.VendorTypeEAP5G,
			VendorData: vendorData,
		},
	}
	return e.Marshal()
}

// decodeEAPExpanded unmarshals a RADIUS EAP-Message attribute's content as an EAP
// packet and returns its EAP-Expanded (vendor-specific, i.e. EAP-5G) type data.
func decodeEAPExpanded(eapMessage []byte) (*eap.EapExpanded, error) {
	e := new(eap.EAP)
	if err := e.Unmarshal(eapMessage); err != nil {
		return nil, err
	}
	if e.Code != eap.EapCodeRequest {
		return nil, errors.New("decodeEAPExpanded: EAP payload is not a request")
	}
	expanded, ok := e.EapTypeData.(*eap.EapExpanded)
	if !ok {
		return nil, errors.New("decodeEAPExpanded: EAP type data is not EAP-Expanded")
	}
	return expanded, nil
}

func marshalEAP5GNotification(identifier uint8) ([]byte, error) {
	vendorData := []byte{eap5GType5GNotification, 0}
	e := &eap.EAP{
		Code:       eap.EapCodeResponse,
		Identifier: identifier,
		EapTypeData: &eap.EapExpanded{
			VendorID:   eap.VendorId3GPP,
			VendorType: eap.VendorTypeEAP5G,
			VendorData: vendorData,
		},
	}
	return e.Marshal()
}
