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

package outline

import (
	"fmt"
	"time"

	"github.com/Jigsaw-Code/outline-go-tun2socks/core"
	"github.com/Jigsaw-Code/outline-go-tun2socks/core/proxy/dnsfallback"
    "gvisor.dev/gvisor/pkg/tcpip/stack"

	oss "github.com/Jigsaw-Code/outline-go-tun2socks/shadowsocks"
    "github.com/Jigsaw-Code/outline-go-tun2socks/tunnel"
	shadowsocks "github.com/Jigsaw-Code/outline-ss-server/client"
)

// OutlineTunnel represents a tunnel from a TUN device to a server.
type Tunnel interface {
	tunnel.Tunnel

	// UpdateUDPSupport determines if UDP is supported following a network connectivity change.
	// Sets the tunnel's UDP connection handler accordingly, falling back to DNS over TCP if UDP is not supported.
	// Returns whether UDP proxying is supported in the new network.
	UpdateUDPSupport() bool
}

type outlinetunnel struct {
	tunnel.Tunnel
    lwipStack    core.LWIPStack
	host         string
	port         int
	password     string
	cipher       string
	isUDPEnabled bool // Whether the tunnel supports proxying UDP.
}

// NewOutlineTunnel connects a tunnel to a Shadowsocks proxy server and returns an `OutlineTunnel`.
//
// `host` is the IP or domain of the Shadowsocks proxy.
// `port` is the port of the Shadowsocks proxy.
// `password` is the password of the Shadowsocks proxy.
// `cipher` is the encryption cipher used by the Shadowsocks proxy.
// `isUDPEnabled` indicates if the Shadowsocks proxy and the network support proxying UDP traffic.
// `in` is the TUN device.
func NewTunnel(host string, port int, password, cipher string, isUDPEnabled bool, link stack.LinkEndpoint) (Tunnel, error) {
	_, err := shadowsocks.NewClient(host, port, password, cipher)
	if err != nil {
		return nil, fmt.Errorf("Invalid Shadowsocks proxy parameters: %v", err.Error())
	}
	t := &outlinetunnel{nil, host, port, password, cipher, isUDPEnabled}
	tcp, udp := t.getConnectionHandlers()
	t.tunnel, err = tunnel.MakeTunnel(link, tcp, udp)
	if err != nil {
		return nil, err
	}
	return t, nil
}

func (t *outlinetunnel) UpdateUDPSupport() bool {
	client, err := shadowsocks.NewClient(t.host, t.port, t.password, t.cipher)
	if err != nil {
		return false
	}
	isUDPEnabled := oss.CheckUDPConnectivityWithDNS(client, shadowsocks.NewAddr("1.1.1.1:53", "udp")) == nil
	if t.isUDPEnabled != isUDPEnabled {
		t.isUDPEnabled = isUDPEnabled
		// TODO: Make this thread-safe.
		_, t.nat.handler = t.getConnectionHandlers()
	}
	return isUDPEnabled
}

// Returns UDP and TCP Shadowsocks connection handlers.
// Returns a DNS/TCP fallback UDP handler when UDP is disabled.
func (t *outlinetunnel) getConnectionHandlers() (core.TCPConnHandler, core.UDPConnHandler) {
	var udpHandler core.UDPConnHandler
	if t.isUDPEnabled {
		udpHandler = oss.NewUDPHandler(t.host, t.port, t.password, t.cipher, 30*time.Second)
	} else {
		udpHandler = dnsfallback.NewUDPHandler()
	}
	tcphandler := oss.NewTCPHandler(t.host, t.port, t.password, t.cipher)
	return tcphandler, udpHandler
}
