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
	"log"
	"net"

	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/waiter"

	"github.com/Jigsaw-Code/outline-go-tun2socks/core"
)

const (
	windowSize = 0
	maxAttempts = 10
)

func tcpbridge(handler core.TCPConnHandler, r *tcp.ForwarderRequest) {
	id := r.ID()
	dstAddr := net.TCPAddr{
		IP:   []byte(id.LocalAddress),
		Port: int(id.LocalPort),
	}
	var q waiter.Queue
	// CreateEndpoint issues the SYNACK.
	// TODO: Delay CreateEndpoint until after connection setup.
	endpoint, stackerr := r.CreateEndpoint(&q)
	if stackerr != nil {
        r.Complete(true)
		log.Printf("Endpoint creation failed for request %v (%s): %v", r, dstAddr.String(), stackerr)
		return
	}
    r.Complete(false) // notify?

	err := handler.Handle(gonet.NewTCPConn(&q, endpoint), &dstAddr)
	if err != nil {
		log.Printf("Proxying failed: %v", err)
	}
	sendRST := err != nil
	r.Complete(sendRST)
}

func tcphandler(handler core.TCPConnHandler) func(*tcp.ForwarderRequest) {
	// The returned function will be run in a fresh goroutine for each incoming socket.
	return func(r *tcp.ForwarderRequest) {
		tcpbridge(handler, r)
	}
}

func newTCPForwarder(s *stack.Stack, handler core.TCPConnHandler) *tcp.Forwarder {
	return tcp.NewForwarder(s, windowSize, maxAttempts, tcphandler(handler))
}
