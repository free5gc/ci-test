package test

import (
	"fmt"
	"net"
)

func connectToUpf(gnbIp, upfIp string, gnbPort, upfPort int) (*net.UDPConn, error) {
	upfAddr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", upfIp, upfPort))
	if err != nil {
		return nil, err
	}
	gnbAddr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", gnbIp, gnbPort))
	if err != nil {
		return nil, err
	}
	return net.DialUDP("udp", gnbAddr, upfAddr)
}
