// Copyright 2020 The Outline Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package tunnel

import (
	"fmt"
	"log"
	"net"
	"sync"
    _ "unsafe"

	"github.com/Jigsaw-Code/outline-go-tun2socks/core"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/buffer"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	// "gvisor.dev/gvisor/pkg/tcpip/transport/udp"
)

const udpNoChecksum bool = true

// Implements core.UDPConn.
type reverseUDPConn struct {
	localAddr tcpip.FullAddress
	route     *stack.Route
	n         *nat
}

func (c reverseUDPConn) LocalAddr() *net.UDPAddr {
	return &net.UDPAddr{IP: net.IP(c.localAddr.Addr), Port: int(c.localAddr.Port)}
}

func (c reverseUDPConn) ReceiveTo(data []byte, addr *net.UDPAddr) error {
	panic("not implemented")
}

func (c reverseUDPConn) WriteFrom(data []byte, addr *net.UDPAddr) (int, error) {
    if addr == nil {
        return 0, fmt.Errorf("%s", tcpip.ErrDestinationRequired)
    }

    v := buffer.View(data)
	if len(v) > header.UDPMaximumPacketSize {
		// Payload can't possibly fit in a packet.
		return 0, fmt.Errorf("%s", tcpip.ErrMessageTooLong)
	}

    r := c.route.Clone()
    defer r.Release()

    vd := v.ToVectorisedView() // TODO: needed?
	if ipv4 := addr.IP.To4(); ipv4 != nil {
		r.LocalAddress = tcpip.Address(ipv4)
	} else {
		r.LocalAddress = tcpip.Address(addr.IP)
	}
    remotePort := c.localAddr.Port
	return _sendUDP(r, vd, uint16(addr.Port), remotePort, udpNoChecksum)
}

/*
func (c reverseUDPConn) WriteFrom(data []byte, addr *net.UDPAddr) (int, error) {
	// Based on sendUDP() in https://github.com/google/gvisor/blob/master/pkg/tcpip/transport/udp/endpoint.go#

	srcIP := tcpip.Address(string(addr.IP))
	protocol := header.IPv6ProtocolNumber
	if ip4 := srcIP.To4(); len(ip4) > 0 {
		srcIP = ip4
		protocol = header.IPv4ProtocolNumber
	}
	route, stackerr := c.stack.FindRoute(nicID, srcIP, c.localAddr.Addr, protocol, false)
	if stackerr != nil {
		return 0, fmt.Errorf("Failed to find route: %v", stackerr)
	}

	if route.IsResolutionRequired() {
		if _, err := route.Resolve(nil); err != nil {
		log.Printf("Route error: %v", err)
			return 0, fmt.Errorf("%v", err)
		}
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
	if stackerr := route.WritePacket(nil, headerParams, pkt); stackerr != nil {
		log.Printf("UDP downstream write error: %v", stackerr)
		return 0, fmt.Errorf("Failed to write packet: %v", stackerr)
	}
	return len(data), nil
}*/

func (c reverseUDPConn) Close() error {
	c.n.Lock()
	delete(c.n.m, c.localAddr)
    c.route.Release()
	c.n.Unlock()
	return nil
}

type nat struct {
	sync.RWMutex
	m       map[tcpip.FullAddress]reverseUDPConn
	handler core.UDPConnHandler
	stack   *stack.Stack
}

func (n *nat) getConn(route *stack.Route, localAddr tcpip.FullAddress, remoteAddr net.UDPAddr) (core.UDPConn, error) {
	// TODO: Avoid lock acquisition on every packet.
	n.Lock()
	defer n.Unlock()
	conn, ok := n.m[localAddr]
	if !ok {
		conn = reverseUDPConn{localAddr, route, n}
		n.m[localAddr] = conn
		if err := n.handler.Connect(conn, &remoteAddr); err != nil {
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
    // Ref: gVisor pkg/tcpip/transport/udp/endpoint.go HandlePacket
    udpHdr := header.UDP(pkt.TransportHeader().View())
    if int(udpHdr.Length()) > pkt.Data.Size()+header.UDPMinimumSize {
        return true // mal pkt
    }

    /*if !verifyChecksum(udpHdr, pkt) {
        return true // xsum err
    }*/
    netHdr := pkt.Network()
    route, stackerr := n.stack.FindRoute(nicID, netHdr.DestinationAddress(), netHdr.SourceAddress(), pkt.NetworkProtocolNumber, false /*mcast loop*/)
    if stackerr != nil {
        log.Printf("Failed to find route: %v", stackerr)
        return false
    }
    route.ResolveWith(pkt.SourceLinkAddress())

	conn, err := n.getConn(route, srcAddr, dstAddr)
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

func newNAT(netstack *stack.Stack, handler core.UDPConnHandler) *nat {
	return &nat{
		stack:   netstack,
		m:       make(map[tcpip.FullAddress]reverseUDPConn),
		handler: handler,
	}
}

// github.com/xjasonlyu/tun2socks/blob/fcf9d280b8/internal/core/udp.go
// _sendUDP wraps sendUDP with some default parameters.
func _sendUDP(r *stack.Route, data buffer.VectorisedView, localPort, remotePort uint16, noChecksum bool) (int, error) {
	if err := sendUDP(r, data, localPort, remotePort, 0 /* ttl */, true /* useDefaultTTL */, 0 /* tos */, nil /* owner */, noChecksum); err != nil {
		return 0, fmt.Errorf("%s", err)
	}
	return data.Size(), nil
}


// sendUDP sends a UDP segment via the provided network endpoint and under the
// provided identity.
//
//go:linkname sendUDP gvisor.dev/gvisor/pkg/tcpip/transport/udp.sendUDP
func sendUDP(r *stack.Route, data buffer.VectorisedView, localPort, remotePort uint16, ttl uint8, useDefaultTTL bool, tos uint8, owner tcpip.PacketOwner, noChecksum bool) *tcpip.Error

// verifyChecksum verifies the checksum unless RX checksum offload is enabled.
// On IPv4, UDP checksum is optional, and a zero value means the transmitter
// omitted the checksum generation (RFC768).
// On IPv6, UDP checksum is not optional (RFC2460 Section 8.1).
//
// goxyzlinkname verifyChecksum gvisor.dev/gvisor/pkg/tcpip/transport
// func verifyChecksum(hdr header.UDP, pkt *stack.PacketBuffer) bool

