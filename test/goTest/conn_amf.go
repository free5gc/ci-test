package test

import (
	"net"

	"github.com/free5gc/sctp"
)

func getNgapIp(amfIP, ranIP string, amfPort, ranPort int) (*sctp.SCTPAddr, *sctp.SCTPAddr, error) {
	ips := make([]net.IPAddr, 0)
	if ip, err := net.ResolveIPAddr("ip", amfIP); err != nil {
		return nil, nil, err
	} else {
		ips = append(ips, *ip)
	}
	amfAddr := &sctp.SCTPAddr{
		IPAddrs: ips,
		Port:    amfPort,
	}
	ips = make([]net.IPAddr, 0)
	if ip, err := net.ResolveIPAddr("ip", ranIP); err != nil {
		return nil, nil, err
	} else {
		ips = append(ips, *ip)
	}
	ranAddr := &sctp.SCTPAddr{
		IPAddrs: ips,
		Port:    ranPort,
	}
	return amfAddr, ranAddr, nil
}

func connectToAmf(amfIp, ranIp string, amfPort, ranPort int) (*sctp.SCTPConn, error) {
	amfAddr, ranAddr, err := getNgapIp(amfIp, ranIp, amfPort, ranPort)
	if err != nil {
		return nil, err
	}
	conn, err := sctp.DialSCTP("sctp", ranAddr, amfAddr)
	if err != nil {
		return nil, err
	}
	info, err := conn.GetDefaultSentParam()
	if err != nil {
		return nil, err
	}
	info.PPID = NGAP_PPID
	if err := conn.SetDefaultSentParam(info); err != nil {
		return nil, err
	}
	return conn, nil
}
