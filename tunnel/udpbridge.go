package tunnel

import (
	"errors"
	"fmt"
	"log"
	"net"
	"sync"

	"github.com/Jigsaw-Code/outline-go-tun2socks/core"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/buffer"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
)

type nat struct {
	sync.RWMutex
	m       map[tcpip.FullAddress]reverseUDPConn
	handler core.UDPConnHandler
	stack   *stack.Stack
}

type reverseUDPConn struct {
	localAddr tcpip.FullAddress
	stack     *stack.Stack
	n         *nat
}

func (c reverseUDPConn) LocalAddr() *net.UDPAddr {
	return &net.UDPAddr{IP: net.IP(c.localAddr.Addr), Port: int(c.localAddr.Port)}
}

func (c reverseUDPConn) ReceiveTo(data []byte, addr *net.UDPAddr) error {
	return errors.New("Why does this method even exist?")
}

func (c reverseUDPConn) WriteFrom(data []byte, addr *net.UDPAddr) (int, error) {
	// Based on sendUDP() in https://github.com/google/gvisor/blob/master/pkg/tcpip/transport/udp/endpoint.go#

	srcIP := tcpip.Address(string(addr.IP))
	protocol := header.IPv6ProtocolNumber
	if ip4 := srcIP.To4(); len(ip4) > 0 {
		srcIP = ip4
		protocol = header.IPv4ProtocolNumber
	}
	route, err := c.stack.FindRoute(1, srcIP, c.localAddr.Addr, protocol, false)
	if err != nil {
		return 0, errors.New(err.String())
	}

	// WritePacket takes ownership of pkt.
	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
		ReserveHeaderBytes: header.UDPMinimumSize + int(route.MaxHeaderLength()),
	})

	// Initialize the UDP header.
	udpHeader := header.UDP(pkt.TransportHeader().Push(header.UDPMinimumSize))
	pkt.TransportProtocolNumber = udp.ProtocolNumber

	// Copy packet contents
	pkt.Data.AppendView(buffer.NewViewFromBytes(data))
	length := uint16(pkt.Size())
	udpHeader.SetSourcePort(uint16(addr.Port))
	udpHeader.SetDestinationPort(c.localAddr.Port)
	udpHeader.SetLength(length)
	xsum := route.PseudoHeaderChecksum(udp.ProtocolNumber, length)
	xsum = header.Checksum(data, xsum)
	udpHeader.SetChecksum(^udpHeader.CalculateChecksum(xsum))
	headerParams := stack.NetworkHeaderParams{
		Protocol: udp.ProtocolNumber,
		TTL:      route.DefaultTTL(),
	}
	if err := route.WritePacket(nil, headerParams, pkt); err != nil {
		log.Printf("UDP download write error: %v", err)
		return 0, errors.New(err.String())
	}
	return len(data), nil
}

func (c reverseUDPConn) Close() error {
	c.n.Lock()
	delete(c.n.m, c.localAddr)
	c.n.Unlock()
	log.Printf("Closing UDP socket for %s", c.LocalAddr().String())
	return nil
}

func (n *nat) getConn(localAddr tcpip.FullAddress, netstack *stack.Stack) (core.UDPConn, error) {
	n.Lock()
	defer n.Unlock()
	conn, ok := n.m[localAddr]
	if !ok {
		conn = reverseUDPConn{localAddr, netstack, n}
		n.m[localAddr] = conn
		if err := n.handler.Connect(conn, nil); err != nil {
			return nil, fmt.Errorf("Error registering connection: %v", err)
		}
	}
	return conn, nil
}

func (n *nat) HandleOutboundPacket(id stack.TransportEndpointID, pkt *stack.PacketBuffer) bool {
	srcAddr := tcpip.FullAddress{
		Addr: id.RemoteAddress,
		Port: id.RemotePort,
	}
	dstAddr := net.UDPAddr{
		IP:   []byte(id.LocalAddress),
		Port: int(id.LocalPort),
	}
	conn, err := n.getConn(srcAddr, n.stack)
	if err != nil {
		log.Printf("UDP upload error: %v", err)
		return false
	}
	if err := n.handler.ReceiveTo(conn, pkt.Data.ToView(), &dstAddr); err != nil {
		log.Printf("UDP upload write error: %v", err)
		return false
	}
	return true
}

func MakeUDPBridge(netstack *stack.Stack, handler core.UDPConnHandler) *nat {
	return &nat{stack: netstack, m: make(map[tcpip.FullAddress]reverseUDPConn), handler: handler}
}
