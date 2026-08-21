package test

// IKEv2/IPsec/EAP-5G/XFRM/GRE client-side logic for the non-3GPP access (N3IWF) IT
// test. Ported from free5gc/test/non3gpp_test.go's shared helpers, adapted for the IT
// topology: the UE side runs from a single container (IT_IP) with XFRM/GRE interfaces
// built on top of its only NIC (IT_IPSEC_IFACE_NAME), rather than a dedicated veth pair
// on a bare-metal host.

import (
	"encoding/binary"
	"fmt"
	"net"
	"testing"

	"github.com/pkg/errors"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"github.com/davecgh/go-spew/spew"

	"github.com/free5gc/ike"
	ike_message "github.com/free5gc/ike/message"
	ike_security "github.com/free5gc/ike/security"

	"github.com/free5gc/nas/ie"
	"github.com/free5gc/nas/message"
	"github.com/free5gc/openapi/models"
	"github.com/free5gc/util/ueauth"
)

var (
	n3iwfInfo_IPSecIfaceAddr     = N3IWF_IP
	n3ueInfo_IPSecIfaceAddr      = IT_IP
	n3ueInfo_SmPolicy_SNSSAI_SST = "1"
	n3ueInfo_SmPolicy_SNSSAI_SD  = SD
	n3ueInfo_IPSecIfaceName      = IT_IPSEC_IFACE_NAME
	n3ueInfo_XfrmiName           = "ipsec"
	n3ueInfo_XfrmiId             = uint32(1)
	n3ueInfo_GreIfaceName        = "gretun"
	ueInnerAddr                  = new(net.IPNet)
)

type N3IWFUe struct {
	N3IWFIkeUe
	N3IWFRanUe
}

type N3IWFIkeUe struct {
	/* IKE Security Association */
	N3IWFIKESecurityAssociation   *IKESecurityAssociation
	N3IWFChildSecurityAssociation map[uint32]*ChildSecurityAssociation // inbound SPI as key

	/* Temporary Mapping of two SPIs */
	// Exchange Message ID(including a SPI) and ChildSA(including a SPI)
	// Mapping of Message ID of exchange in IKE and Child SA when creating new child SA
	TemporaryExchangeMsgIDChildSAMapping map[uint32]*ChildSecurityAssociation // Message ID as a key
}

type N3IWFRanUe struct {
	/* UE identity */
	RanUeNgapId int64
	AmfUeNgapId int64
}

type IKESecurityAssociation struct {
	*ike_security.IKESAKey
	// SPI
	RemoteSPI uint64
	LocalSPI  uint64

	// Message ID
	InitiatorMessageID uint32
	ResponderMessageID uint32

	// Authentication data
	ResponderSignedOctets []byte

	// Used for key generating
	ConcatenatedNonce []byte

	// Temporary data stored for the use in later exchange
	IKEAuthResponseSA *ike_message.SecurityAssociation
}

type ChildSecurityAssociation struct {
	*ike_security.ChildSAKey

	// SPI
	InboundSPI  uint32 // N3IWF Specify
	OutboundSPI uint32 // Non-3GPP UE Specify

	// IP address
	PeerPublicIPAddr  net.IP
	LocalPublicIPAddr net.IP

	// Traffic selector
	SelectedIPProtocol    uint8
	TrafficSelectorLocal  net.IPNet
	TrafficSelectorRemote net.IPNet
}

type PDUQoSInfo struct {
	pduSessionID    uint8
	qfiList         []uint8
	isDefault       bool
	isDSCPSpecified bool
}

func (ikeUe *N3IWFIkeUe) CreateHalfChildSA(msgID, inboundSPI uint32, pduSessionID int64) {
	childSA := new(ChildSecurityAssociation)
	childSA.InboundSPI = inboundSPI
	// Map Exchange Message ID and Child SA data until get paired response
	ikeUe.TemporaryExchangeMsgIDChildSAMapping[msgID] = childSA
}

func (ikeUe *N3IWFIkeUe) CompleteChildSA(msgID uint32, outboundSPI uint32,
	chosenSecurityAssociation *ike_message.SecurityAssociation,
) (*ChildSecurityAssociation, error) {
	childSA, ok := ikeUe.TemporaryExchangeMsgIDChildSAMapping[msgID]
	if !ok {
		return nil, errors.Errorf(
			"CompleteChildSA(): There's not a half child SA created by the exchange with message ID %d.", msgID)
	}

	// Remove mapping of exchange msg ID and child SA
	delete(ikeUe.TemporaryExchangeMsgIDChildSAMapping, msgID)

	if chosenSecurityAssociation == nil {
		return nil, errors.Errorf("CompleteChildSA(): chosenSecurityAssociation is nil")
	}
	if len(chosenSecurityAssociation.Proposals) == 0 {
		return nil, errors.Errorf("CompleteChildSA(): No proposal")
	}

	childSA.OutboundSPI = outboundSPI

	var err error
	childSA.ChildSAKey, err = ike_security.NewChildSAKeyByProposal(chosenSecurityAssociation.Proposals[0])
	if err != nil {
		return nil, errors.Wrapf(err, "CompleteChildSA")
	}

	// Record to UE context with inbound SPI as key
	ikeUe.N3IWFChildSecurityAssociation[childSA.InboundSPI] = childSA

	return childSA, nil
}

func generateSPI(n3ue *N3IWFUe) ([]byte, error) {
	var spi uint32
	spiByte := make([]byte, 4)
	for {
		randomBigInt, err := ike_security.GenerateRandomNumber()
		if err != nil {
			return nil, errors.Wrapf(err, "GenerateSPI()")
		}
		randomUint64 := randomBigInt.Uint64()
		if _, ok := n3ue.N3IWFChildSecurityAssociation[uint32(randomUint64)]; !ok {
			spi = uint32(randomUint64)
			binary.BigEndian.PutUint32(spiByte, spi)
			break
		}
	}
	return spiByte, nil
}

func setupUDPSocket() (*net.UDPConn, error) {
	bindAddr := fmt.Sprintf("%s:%d", n3ueInfo_IPSecIfaceAddr, N3IWF_IKE_PORT)
	udpAddr, err := net.ResolveUDPAddr("udp", bindAddr)
	if err != nil {
		return nil, fmt.Errorf("Resolve UDP address failed: %+v", err)
	}
	udpListener, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return nil, fmt.Errorf("Resolve UDP address failed: %+v", err)
	}
	return udpListener, nil
}

func setupIPsecXfrmi(xfrmIfaceName, parentIfaceName string, xfrmIfaceId uint32, xfrmIfaceAddr *net.IPNet) (netlink.Link, error) {
	var (
		xfrmi, parent netlink.Link
		err           error
	)

	if parent, err = netlink.LinkByName(parentIfaceName); err != nil {
		return nil, err
	}

	link := &netlink.Xfrmi{
		LinkAttrs: netlink.LinkAttrs{
			MTU:         1478,
			Name:        xfrmIfaceName,
			ParentIndex: parent.Attrs().Index,
		},
		Ifid: xfrmIfaceId,
	}

	// ip link add
	if err := netlink.LinkAdd(link); err != nil {
		return nil, err
	}

	if xfrmi, err = netlink.LinkByName(xfrmIfaceName); err != nil {
		return nil, err
	}

	// ip addr add
	linkIPSecAddr := &netlink.Addr{
		IPNet: xfrmIfaceAddr,
	}

	if err := netlink.AddrAdd(xfrmi, linkIPSecAddr); err != nil {
		return nil, err
	}

	// ip link set ... up
	if err := netlink.LinkSetUp(xfrmi); err != nil {
		return nil, err
	}

	return xfrmi, nil
}

func setupGreTunnel(greIfaceName, parentIfaceName string, ueTunnelAddr, n3iwfTunnelAddr, pduAddr net.IP, qoSInfo *PDUQoSInfo, t *testing.T) (netlink.Link, error) {
	var (
		parent      netlink.Link
		greKeyField uint32
		err         error
	)

	if qoSInfo != nil {
		greKeyField |= (uint32(qoSInfo.qfiList[0]) & 0x3F) << 24
	}

	if parent, err = netlink.LinkByName(parentIfaceName); err != nil {
		return nil, err
	}

	// New GRE tunnel interface
	newGRETunnel := &netlink.Gretun{
		LinkAttrs: netlink.LinkAttrs{
			Name: greIfaceName,
			MTU:  1438, // remain for endpoint IP header(most 40 bytes if IPv6) and ESP header (22 bytes)
		},
		Link:   uint32(parent.Attrs().Index), // PHYS_DEV in iproute2; IFLA_GRE_LINK in linux kernel
		Local:  ueTunnelAddr,
		Remote: n3iwfTunnelAddr,
		IKey:   greKeyField,
		OKey:   greKeyField,
	}

	t.Logf("GRE Key Field: 0x%x", greKeyField)

	if err := netlink.LinkAdd(newGRETunnel); err != nil {
		return nil, err
	}

	// Get link info
	linkGRE, err := netlink.LinkByName(greIfaceName)
	if err != nil {
		return nil, fmt.Errorf("No link named %s", greIfaceName)
	}

	linkGREAddr := &netlink.Addr{
		IPNet: &net.IPNet{
			IP:   pduAddr,
			Mask: net.IPv4Mask(255, 255, 255, 255),
		},
	}

	if err := netlink.AddrAdd(linkGRE, linkGREAddr); err != nil {
		return nil, err
	}

	// Set GRE interface up
	if err := netlink.LinkSetUp(linkGRE); err != nil {
		return nil, err
	}

	return linkGRE, nil
}

// buildEAP5GANParameters builds the AN-Parameters carried in the EAP-Response/5G-NAS
// message that starts EAP-5G (TS 24.502 9.3.2.2.2, TS 24.501 8.2.6.1.1): GUAMI, PLMN
// ID, Establishment Cause, and Requested NSSAI (both slices supported by this IT
// environment, matching const.go's SD and SD_2).
func buildEAP5GANParameters() []byte {
	var anParameters []byte

	// Build GUAMI. PLMN part matches PLMN_OCT; AMF ID "\xca\xfe\x00" matches amfCfg.yaml's amfId.
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

	// Build Establishment Cause
	anParameter = make([]byte, 2)
	establishmentCause := make([]byte, 1)
	establishmentCause[0] = ike_message.EstablishmentCauseMO_Signaling
	anParameter[0] = ike_message.ANParametersTypeEstablishmentCause
	anParameter[1] = byte(len(establishmentCause))
	anParameter = append(anParameter, establishmentCause...)

	anParameters = append(anParameters, anParameter...)

	// Build PLMN ID
	anParameter = make([]byte, 2)
	plmnID := []byte(PLMN_OCT)
	anParameter[0] = ike_message.ANParametersTypeSelectedPLMNID
	anParameter[1] = byte(len(plmnID))
	anParameter = append(anParameter, plmnID...)

	anParameters = append(anParameters, anParameter...)

	// Build NSSAI: both slices this IT environment supports (see const.go SD/SD_2)
	anParameter = make([]byte, 2)
	var nssai []byte
	// s-nssai = s-nssai length(1 byte) | SST(1 byte) | SD(3 bytes)
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

	return anParameters
}

func parseIPAddressInformationToChildSecurityAssociation(
	childSecurityAssociation *ChildSecurityAssociation,
	trafficSelectorLocal *ike_message.IndividualTrafficSelector,
	trafficSelectorRemote *ike_message.IndividualTrafficSelector,
) error {
	if childSecurityAssociation == nil {
		return errors.New("childSecurityAssociation is nil")
	}

	childSecurityAssociation.PeerPublicIPAddr = net.ParseIP(n3iwfInfo_IPSecIfaceAddr)
	childSecurityAssociation.LocalPublicIPAddr = net.ParseIP(n3ueInfo_IPSecIfaceAddr)

	childSecurityAssociation.TrafficSelectorLocal = net.IPNet{
		IP:   trafficSelectorLocal.StartAddress,
		Mask: []byte{255, 255, 255, 255},
	}

	childSecurityAssociation.TrafficSelectorRemote = net.IPNet{
		IP:   trafficSelectorRemote.StartAddress,
		Mask: []byte{255, 255, 255, 255},
	}
	return nil
}

func parse5GQoSInfoNotify(n *ike_message.Notification) (info *PDUQoSInfo, err error) {
	info = new(PDUQoSInfo)
	var offset = 0
	data := n.NotificationData
	dataLen := int(data[0])
	info.pduSessionID = data[1]
	qfiListLen := int(data[2])
	offset += (3 + qfiListLen)

	if offset > dataLen {
		return nil, errors.New("parse5GQoSInfoNotify err: Length and content of 5G-QoS-Info-Notify mismatch")
	}

	info.qfiList = make([]byte, qfiListLen)
	copy(info.qfiList, data[3:3+qfiListLen])

	info.isDefault = (data[offset] & ike_message.NotifyType5G_QOS_INFOBitDCSICheck) > 0
	info.isDSCPSpecified = (data[offset] & ike_message.NotifyType5G_QOS_INFOBitDSCPICheck) > 0

	return
}

type XFRMEncryptionAlgorithmType uint16

func (xfrmEncryptionAlgorithmType XFRMEncryptionAlgorithmType) String() string {
	switch xfrmEncryptionAlgorithmType {
	case ike_message.ENCR_DES:
		return "cbc(des)"
	case ike_message.ENCR_3DES:
		return "cbc(des3_ede)"
	case ike_message.ENCR_CAST:
		return "cbc(cast5)"
	case ike_message.ENCR_BLOWFISH:
		return "cbc(blowfish)"
	case ike_message.ENCR_NULL:
		return "ecb(cipher_null)"
	case ike_message.ENCR_AES_CBC:
		return "cbc(aes)"
	case ike_message.ENCR_AES_CTR:
		return "rfc3686(ctr(aes))"
	default:
		return ""
	}
}

type XFRMIntegrityAlgorithmType uint16

func (xfrmIntegrityAlgorithmType XFRMIntegrityAlgorithmType) String() string {
	switch xfrmIntegrityAlgorithmType {
	case ike_message.AUTH_HMAC_MD5_96:
		return "hmac(md5)"
	case ike_message.AUTH_HMAC_SHA1_96:
		return "hmac(sha1)"
	case ike_message.AUTH_AES_XCBC_96:
		return "xcbc(aes)"
	default:
		return ""
	}
}

func applyXFRMRule(ue_is_initiator bool, ifId uint32, childSecurityAssociation *ChildSecurityAssociation) error {
	// Direction: N3IWF -> UE
	// State
	var xfrmEncryptionAlgorithm, xfrmIntegrityAlgorithm *netlink.XfrmStateAlgo
	if ue_is_initiator {
		xfrmEncryptionAlgorithm = &netlink.XfrmStateAlgo{
			Name: XFRMEncryptionAlgorithmType(childSecurityAssociation.EncrKInfo.TransformID()).String(),
			Key:  childSecurityAssociation.ResponderToInitiatorEncryptionKey,
		}
		if childSecurityAssociation.IntegKInfo != nil {
			xfrmIntegrityAlgorithm = &netlink.XfrmStateAlgo{
				Name: XFRMIntegrityAlgorithmType(childSecurityAssociation.IntegKInfo.TransformID()).String(),
				Key:  childSecurityAssociation.ResponderToInitiatorIntegrityKey,
			}
		}
	} else {
		xfrmEncryptionAlgorithm = &netlink.XfrmStateAlgo{
			Name: XFRMEncryptionAlgorithmType(childSecurityAssociation.EncrKInfo.TransformID()).String(),
			Key:  childSecurityAssociation.InitiatorToResponderEncryptionKey,
		}
		if childSecurityAssociation.IntegKInfo != nil {
			xfrmIntegrityAlgorithm = &netlink.XfrmStateAlgo{
				Name: XFRMIntegrityAlgorithmType(childSecurityAssociation.IntegKInfo.TransformID()).String(),
				Key:  childSecurityAssociation.InitiatorToResponderIntegrityKey,
			}
		}
	}

	xfrmState := new(netlink.XfrmState)

	xfrmState.Src = childSecurityAssociation.PeerPublicIPAddr
	xfrmState.Dst = childSecurityAssociation.LocalPublicIPAddr
	xfrmState.Proto = netlink.XFRM_PROTO_ESP
	xfrmState.Mode = netlink.XFRM_MODE_TUNNEL
	xfrmState.Spi = int(childSecurityAssociation.InboundSPI)
	xfrmState.Ifid = int(ifId)
	xfrmState.Auth = xfrmIntegrityAlgorithm
	xfrmState.Crypt = xfrmEncryptionAlgorithm
	xfrmState.ESN = childSecurityAssociation.EsnInfo.GetNeedESN()

	// Commit xfrm state to netlink
	var err error
	if err = netlink.XfrmStateAdd(xfrmState); err != nil {
		return fmt.Errorf("Set XFRM state rule failed: %+v", err)
	}

	// Policy
	xfrmPolicyTemplate := netlink.XfrmPolicyTmpl{
		Src:   xfrmState.Src,
		Dst:   xfrmState.Dst,
		Proto: xfrmState.Proto,
		Mode:  xfrmState.Mode,
		Spi:   xfrmState.Spi,
	}

	xfrmPolicy := new(netlink.XfrmPolicy)

	if childSecurityAssociation.SelectedIPProtocol == 0 {
		return errors.New("Protocol == 0")
	}

	xfrmPolicy.Src = &childSecurityAssociation.TrafficSelectorRemote
	xfrmPolicy.Dst = &childSecurityAssociation.TrafficSelectorLocal
	xfrmPolicy.Proto = netlink.Proto(childSecurityAssociation.SelectedIPProtocol)
	xfrmPolicy.Dir = netlink.XFRM_DIR_IN
	xfrmPolicy.Ifid = int(ifId)
	xfrmPolicy.Tmpls = []netlink.XfrmPolicyTmpl{
		xfrmPolicyTemplate,
	}

	// Commit xfrm policy to netlink
	if err = netlink.XfrmPolicyAdd(xfrmPolicy); err != nil {
		return fmt.Errorf("Set XFRM policy rule failed: %+v", err)
	}

	// Direction: UE -> N3IWF
	// State
	if ue_is_initiator {
		xfrmEncryptionAlgorithm.Key = childSecurityAssociation.InitiatorToResponderEncryptionKey
		if childSecurityAssociation.IntegKInfo != nil {
			xfrmIntegrityAlgorithm.Key = childSecurityAssociation.InitiatorToResponderIntegrityKey
		}
	} else {
		xfrmEncryptionAlgorithm.Key = childSecurityAssociation.ResponderToInitiatorEncryptionKey
		if childSecurityAssociation.IntegKInfo != nil {
			xfrmIntegrityAlgorithm.Key = childSecurityAssociation.ResponderToInitiatorIntegrityKey
		}
	}

	xfrmState.Src, xfrmState.Dst = xfrmState.Dst, xfrmState.Src
	xfrmState.Spi = int(childSecurityAssociation.OutboundSPI)

	// Commit xfrm state to netlink
	if err = netlink.XfrmStateAdd(xfrmState); err != nil {
		return fmt.Errorf("Set XFRM state rule failed: %+v", err)
	}

	// Policy
	xfrmPolicyTemplate.Src, xfrmPolicyTemplate.Dst = xfrmPolicyTemplate.Dst, xfrmPolicyTemplate.Src
	xfrmPolicyTemplate.Spi = int(childSecurityAssociation.OutboundSPI)

	xfrmPolicy.Src, xfrmPolicy.Dst = xfrmPolicy.Dst, xfrmPolicy.Src
	xfrmPolicy.Dir = netlink.XFRM_DIR_OUT
	xfrmPolicy.Tmpls = []netlink.XfrmPolicyTmpl{
		xfrmPolicyTemplate,
	}

	// Commit xfrm policy to netlink
	if err = netlink.XfrmPolicyAdd(xfrmPolicy); err != nil {
		return fmt.Errorf("Set XFRM policy rule failed: %+v", err)
	}
	return nil
}

// sendPduSessionEstablishmentRequest requests an additional PDU session over the
// already-established IKE/NAS-TCP connection to N3IWF (used for the 2nd/3rd/4th PDU
// sessions in TestNon3GPPUE; the 1st goes through the IKE_AUTH CREATE_CHILD_SA flow
// inline in the test body). Sets up a new XFRM interface + GRE tunnel per session.
func sendPduSessionEstablishmentRequest(
	pduSessionId uint8,
	ue *RanUeContext,
	n3Info *N3IWFUe,
	ikeSA *IKESecurityAssociation,
	ikeConn *net.UDPConn,
	nasConn *net.TCPConn,
	t *testing.T,
) ([]netlink.Link, error) {
	var ifaces []netlink.Link

	sst := SST
	sNssai := models.Snssai{
		Sst: int32(sst),
		Sd:  n3ueInfo_SmPolicy_SNSSAI_SD,
	}

	// PDU session establishment request
	pdu := GetUlNasTransport_PduSessionEstablishmentRequest(pduSessionId, ie.ReqType_InitialReq, "internet", &sNssai)
	pdu, err := EncodeNasPduInEnvelopeWithSecurity(ue, pdu, message.SecHdrTypeIntegrityProtectedAndCiphered, true, false)
	if err != nil {
		return ifaces, fmt.Errorf("Encode NAS PDU In Envelope Fail:%+v", err)
	}
	if _, err = nasConn.Write(pdu); err != nil {
		return ifaces, fmt.Errorf("Send NAS Message Fail:%+v", err)
	}

	buffer := make([]byte, 65535)

	t.Logf("Waiting for N3IWF reply from IKE")

	// Receive N3IWF reply
	n, _, err := ikeConn.ReadFromUDP(buffer)
	if err != nil {
		return ifaces, fmt.Errorf("Read IKE Message Fail:%+v", err)
	}

	ikeMessage := new(ike_message.IKEMessage)
	ikeMessage.Payloads.Reset()
	ikeMessage, err = ike.DecodeDecrypt(buffer[:n], nil,
		ikeSA.IKESAKey, ike_message.Role_Initiator)
	if err != nil {
		t.Fatalf("Decode IKE meesage: %v", err)
	}

	var qoSInfo *PDUQoSInfo

	var responseSecurityAssociation *ike_message.SecurityAssociation
	var responseTrafficSelectorInitiator *ike_message.TrafficSelectorInitiator
	var responseTrafficSelectorResponder *ike_message.TrafficSelectorResponder
	var outboundSPI uint32
	var upIPAddr net.IP
	for _, ikePayload := range ikeMessage.Payloads {
		switch ikePayload.Type() {
		case ike_message.TypeSA:
			responseSecurityAssociation = ikePayload.(*ike_message.SecurityAssociation)
			outboundSPI = binary.BigEndian.Uint32(responseSecurityAssociation.Proposals[0].SPI)
		case ike_message.TypeTSi:
			responseTrafficSelectorInitiator = ikePayload.(*ike_message.TrafficSelectorInitiator)
		case ike_message.TypeTSr:
			responseTrafficSelectorResponder = ikePayload.(*ike_message.TrafficSelectorResponder)
		case ike_message.TypeN:
			notification := ikePayload.(*ike_message.Notification)
			if notification.NotifyMessageType == ike_message.Vendor3GPPNotifyType5G_QOS_INFO {
				t.Logf("Received Qos Flow settings")
				if info, err := parse5GQoSInfoNotify(notification); err == nil {
					qoSInfo = info
					t.Logf("NotificationData:%+v", notification.NotificationData)
					if qoSInfo.isDSCPSpecified {
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
			ikeSA.ConcatenatedNonce = responseNonce.NonceData
		}
	}

	// IKE CREATE_CHILD_SA response
	ikeMessage.Payloads.Reset()
	n3Info.N3IWFIKESecurityAssociation.ResponderMessageID = ikeMessage.MessageID

	var ikePayload ike_message.IKEPayloadContainer
	ikePayload.Reset()

	// SA
	inboundSPI, err := generateSPI(n3Info)
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
	localNonceBigInt, err := ike_security.GenerateRandomNumber()
	if err != nil {
		t.Fatalf("Generate local nonce: %v", err)
	}
	localNonce := localNonceBigInt.Bytes()
	ikeSA.ConcatenatedNonce = append(ikeSA.ConcatenatedNonce, localNonce...)
	ikePayload.BuildNonce(localNonce)

	ikeMessage = ike_message.NewMessage(
		ikeSA.LocalSPI,
		ikeSA.RemoteSPI,
		ike_message.CREATE_CHILD_SA,
		true, true,
		ikeSA.ResponderMessageID,
		ikePayload,
	)

	ikeMessageData, err := ike.EncodeEncrypt(ikeMessage, ikeSA.IKESAKey,
		ike_message.Role_Initiator)
	if err != nil {
		t.Fatalf("EncodeEncrypt IKE message failed: %+v", err)
	}

	n3iwfUDPAddr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", n3iwfInfo_IPSecIfaceAddr, N3IWF_IKE_PORT))
	if err != nil {
		return ifaces, fmt.Errorf("Resolve N3IWF IPSec IP Addr Fail:%+v", err)
	}

	_, err = ikeConn.WriteToUDP(ikeMessageData, n3iwfUDPAddr)
	if err != nil {
		t.Errorf("Write IKE maessage fail: %+v", err)
		return ifaces, err
	}

	n3Info.CreateHalfChildSA(n3Info.N3IWFIKESecurityAssociation.ResponderMessageID, binary.BigEndian.Uint32(inboundSPI), int64(pduSessionId))
	childSecurityAssociationContextUserPlane, err := n3Info.CompleteChildSA(
		n3Info.N3IWFIKESecurityAssociation.ResponderMessageID, outboundSPI, responseSecurityAssociation)
	if err != nil {
		return ifaces, fmt.Errorf("Create child security association context failed: %+v", err)
	}

	err = parseIPAddressInformationToChildSecurityAssociation(
		childSecurityAssociationContextUserPlane,
		responseTrafficSelectorResponder.TrafficSelectors[0],
		responseTrafficSelectorInitiator.TrafficSelectors[0])
	if err != nil {
		return ifaces, fmt.Errorf("Parse IP address to child security association failed: %+v", err)
	}
	// Select GRE traffic
	childSecurityAssociationContextUserPlane.SelectedIPProtocol = unix.IPPROTO_GRE

	if err := childSecurityAssociationContextUserPlane.GenerateKeyForChildSA(ikeSA.IKESAKey,
		ikeSA.ConcatenatedNonce); err != nil {
		return ifaces, fmt.Errorf("Generate key for child SA failed: %+v", err)
	}

	// ====== Inbound ======
	t.Logf("====== IPSec/Child SA for 3GPP UP Inbound =====")
	t.Logf("[UE:%+v] <- [N3IWF:%+v]",
		childSecurityAssociationContextUserPlane.LocalPublicIPAddr, childSecurityAssociationContextUserPlane.PeerPublicIPAddr)
	t.Logf("IPSec SPI: 0x%016x", childSecurityAssociationContextUserPlane.InboundSPI)
	t.Logf("IPSec Encryption Algorithm: %d", childSecurityAssociationContextUserPlane.EncrKInfo.TransformID())
	t.Logf("IPSec Encryption Key: 0x%x", childSecurityAssociationContextUserPlane.InitiatorToResponderEncryptionKey)
	t.Logf("IPSec Integrity  Algorithm: %d", childSecurityAssociationContextUserPlane.IntegKInfo.TransformID())
	t.Logf("IPSec Integrity  Key: 0x%x", childSecurityAssociationContextUserPlane.InitiatorToResponderIntegrityKey)
	// ====== Outbound ======
	t.Logf("====== IPSec/Child SA for 3GPP UP Outbound =====")
	t.Logf("[UE:%+v] -> [N3IWF:%+v]",
		childSecurityAssociationContextUserPlane.LocalPublicIPAddr, childSecurityAssociationContextUserPlane.PeerPublicIPAddr)
	t.Logf("IPSec SPI: 0x%016x", childSecurityAssociationContextUserPlane.OutboundSPI)
	t.Logf("IPSec Encryption Algorithm: %d", childSecurityAssociationContextUserPlane.EncrKInfo.TransformID())
	t.Logf("IPSec Encryption Key: 0x%x", childSecurityAssociationContextUserPlane.ResponderToInitiatorEncryptionKey)
	t.Logf("IPSec Integrity  Algorithm: %d", childSecurityAssociationContextUserPlane.IntegKInfo.TransformID())
	t.Logf("IPSec Integrity  Key: 0x%x", childSecurityAssociationContextUserPlane.ResponderToInitiatorIntegrityKey)
	t.Logf("State function: encr: %d, auth: %d", childSecurityAssociationContextUserPlane.EncrKInfo.TransformID(),
		childSecurityAssociationContextUserPlane.IntegKInfo.TransformID())

	// Apply XFRM rules
	n3ueInfo_XfrmiId++
	err = applyXFRMRule(false, n3ueInfo_XfrmiId, childSecurityAssociationContextUserPlane)
	if err != nil {
		t.Errorf("Applying XFRM rules failed: %+v", err)
		return ifaces, err
	}

	var linkIPSec netlink.Link

	// Setup interface for ipsec
	newXfrmiName := fmt.Sprintf("%s-%d", n3ueInfo_XfrmiName, n3ueInfo_XfrmiId)
	if linkIPSec, err = setupIPsecXfrmi(newXfrmiName, n3ueInfo_IPSecIfaceName, n3ueInfo_XfrmiId, ueInnerAddr); err != nil {
		return ifaces, fmt.Errorf("Setup XFRMi interface %s fail: %+v", newXfrmiName, err)
	}

	ifaces = append(ifaces, linkIPSec)

	t.Logf("Setup XFRM interface %s successfully", newXfrmiName)

	var pduAddr net.IP

	// Read NAS from N3IWF
	if n, err := nasConn.Read(buffer); err != nil {
		return ifaces, fmt.Errorf("Read NAS Message Fail:%+v", err)
	} else {
		nasMsg, err := DecodePDUSessionEstablishmentAccept(ue, n, buffer)
		if err != nil {
			t.Errorf("DecodePDUSessionEstablishmentAccept Fail: %+v", err)
		}
		spew.Config.Indent = "\t"
		nasStr := spew.Sdump(nasMsg)
		t.Log("Dump DecodePDUSessionEstablishmentAccept:\n", nasStr)

		pduAddr, err = GetPDUAddress(nasMsg)
		if err != nil {
			t.Errorf("GetPDUAddress Fail: %+v", err)
		}

		t.Logf("PDU Address: %s", pduAddr.String())
	}

	var linkGRE netlink.Link

	newGREName := fmt.Sprintf("%s-id-%d", n3ueInfo_GreIfaceName, n3ueInfo_XfrmiId)

	if linkGRE, err = setupGreTunnel(newGREName, newXfrmiName, ueInnerAddr.IP, upIPAddr, pduAddr, qoSInfo, t); err != nil {
		return ifaces, fmt.Errorf("Setup GRE tunnel %s Fail %+v", newGREName, err)
	}

	ifaces = append(ifaces, linkGRE)

	return ifaces, nil
}

// deriveKn3iwf derives the N3IWF key (Kn3iwf) from Kamf, per TS 33.501 A.9, used to
// authenticate the UE to N3IWF in the IKE_AUTH Authentication payload.
func deriveKn3iwf(ue *RanUeContext) ([]byte, error) {
	P0 := make([]byte, 4)
	binary.BigEndian.PutUint32(P0, ue.ULCount.Get()-1)
	L0 := ueauth.KDFLen(P0)
	P1 := []byte{byte(message.AccessTypeNon3GPP)}
	L1 := ueauth.KDFLen(P1)

	return ueauth.GetKDFValue(ue.Kamf, ueauth.FC_FOR_KGNB_KN3IWF_DERIVATION, P0, L0, P1, L1)
}
