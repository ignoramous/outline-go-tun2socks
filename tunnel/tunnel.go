// Copyright 2019 The Outline Authors
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

	"github.com/Jigsaw-Code/outline-go-tun2socks/core"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
)

// Tunnel represents a session on a TUN device.
type Tunnel interface {
	// IsConnected indicates whether the tunnel is in a connected state.
	IsConnected() bool
	// Disconnect disconnects the tunnel.
	Disconnect()
}

const nicID = 1

func MakeTunnel(link stack.LinkEndpoint, tcpHandler core.TCPConnHandler, udpHandler core.UDPConnHandler) (*tunnel, error) {
	netstack := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol},
		HandleLocal:        false, // false to force all traffic to be forwarded.
	})
	// NIC is initially disabled so it can be configured first.
	options := stack.NICOptions{Disabled: true}
	if stackerr := netstack.CreateNICWithOptions(nicID, link, options); stackerr != nil {
		return nil, fmt.Errorf("Failed to create NIC: %v", stackerr)
	}
	// Route everything
	netstack.SetRouteTable([]tcpip.Route{
		{NIC: nicID, Destination: header.IPv6EmptySubnet},
		{NIC: nicID, Destination: header.IPv4EmptySubnet},
	})
	if stackerr := netstack.SetSpoofing(nicID, true); stackerr != nil {
		return nil, fmt.Errorf("Failed to SetSpoofing: %v", stackerr)
	}
	if stackerr := netstack.SetPromiscuousMode(nicID, true); stackerr != nil {
		return nil, fmt.Errorf("Failed to set promiscuous: %v", stackerr)
	}

	tcpForwarder := newTCPForwarder(netstack, tcpHandler)
	netstack.SetTransportProtocolHandler(tcp.ProtocolNumber, tcpForwarder.HandlePacket)
	udpNAT := newNAT(netstack, udpHandler)
	netstack.SetTransportProtocolHandler(udp.ProtocolNumber, udpNAT.HandleOutboundPacket)

	if stackerr := netstack.EnableNIC(nicID); stackerr != nil {
		return nil, fmt.Errorf("Failed to enable NIC: %v", stackerr)
	}
	return &tunnel{netstack, link, true, udpNAT}, nil
}

type tunnel struct {
	netstack    *stack.Stack
	link        stack.LinkEndpoint
	isConnected bool
	nat         *nat
}

func (t *tunnel) IsConnected() bool {
	return t.isConnected
}

func (t *tunnel) Disconnect() {
	if !t.isConnected {
		return
	}
	t.isConnected = false
	t.netstack.Close()
}
