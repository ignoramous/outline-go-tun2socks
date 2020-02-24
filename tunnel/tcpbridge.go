package tunnel

import (
	"errors"
	"io"
	"log"
	"net"
	"sync"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/buffer"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/waiter"

	"github.com/Jigsaw-Code/outline-go-tun2socks/core"
)

type bridgeConn struct {
	endpoint    tcpip.Endpoint
	q           *waiter.Queue
	pending     []byte
	closedMu    sync.Mutex
	readClosed  bool
	writeClosed bool
}

func (c *bridgeConn) Read(b []byte) (n int, err error) {
	if len(c.pending) > 0 {
		n := copy(b, c.pending)
		c.pending = c.pending[n:]
		return n, nil
	}
	waitEntry, notifyCh := waiter.NewChannelEntry(nil)
	c.q.EventRegister(&waitEntry, waiter.EventIn)
	defer c.q.EventUnregister(&waitEntry)
	for {
		v, _, err := c.endpoint.Read(nil)
		if err == tcpip.ErrWouldBlock {
			<-notifyCh
			continue
		}
		n := copy(b, v)
		c.pending = v[n:]
		if err == tcpip.ErrClosedForReceive {
			if n == len(v) {
				return n, io.EOF
			}
			return n, nil
		} else if err != nil {
			return n, errors.New(err.String())
		} else if n > 0 {
			return n, nil
		}
	}
}

func (c *bridgeConn) Write(b []byte) (n int, err error) {
	// endpoint.Write takes ownership of any input, so make a copy.
	// TODO: Find a way to avoid this copy!
	v := buffer.NewView(len(b))
	copy(v, b)
	waitEntry, notifyCh := waiter.NewChannelEntry(nil)
	c.q.EventRegister(&waitEntry, waiter.EventOut)
	defer c.q.EventUnregister(&waitEntry)
	written := 0
	for {
		n, _, err := c.endpoint.Write(tcpip.SlicePayload(v), tcpip.WriteOptions{})
		written += int(n)
		v.TrimFront(int(n))
		if err == tcpip.ErrWouldBlock || err == nil && len(v) > 0 {
			<-notifyCh
			continue
		} else if err != nil {
			return written, errors.New(err.String()) // TODO EOF
		} else if len(v) == 0 {
			return written, nil
		}
	}
}

func (c *bridgeConn) Close() error {
	c.endpoint.Close()
	return nil
}

func (c *bridgeConn) LocalAddr() net.Addr {
	panic("not implemented") // TODO: Implement
}

func (c *bridgeConn) RemoteAddr() net.Addr {
	panic("not implemented") // TODO: Implement
}

func (c *bridgeConn) SetDeadline(t time.Time) error {
	panic("not implemented") // TODO: Implement
}

func (c *bridgeConn) SetReadDeadline(t time.Time) error {
	panic("not implemented") // TODO: Implement
}

func (c *bridgeConn) SetWriteDeadline(t time.Time) error {
	panic("not implemented") // TODO: Implement
}

func (c *bridgeConn) CloseRead() error {
	err := c.endpoint.Shutdown(tcpip.ShutdownRead)
	c.closedMu.Lock()
	c.readClosed = true
	if c.writeClosed {
		c.endpoint.Close()
	}
	c.closedMu.Unlock()
	if err != nil {
		return errors.New(err.String())
	}
	return nil
}

func (c *bridgeConn) CloseWrite() error {
	err := c.endpoint.Shutdown(tcpip.ShutdownWrite)
	c.closedMu.Lock()
	c.writeClosed = true
	if c.readClosed {
		c.endpoint.Close()
	}
	c.closedMu.Unlock()
	if err != nil {
		return errors.New(err.String())
	}
	return nil
}

func tcpbridge(handler core.TCPConnHandler, r *tcp.ForwarderRequest) {
	id := r.ID()
	dstAddr := net.TCPAddr{
		IP:   []byte(id.LocalAddress),
		Port: int(id.LocalPort),
	}
	var q waiter.Queue
	endpoint, stackerr := r.CreateEndpoint(&q) // SYNACK
	if stackerr != nil {
		log.Printf("Endpoint creation failed for request %v (%s): %v", r, dstAddr.String(), stackerr)
		return
	}

	conn := bridgeConn{endpoint: endpoint, q: &q}
	err := handler.Handle(&conn, &dstAddr)
	if err != nil {
		log.Printf("Proxying failed: %v", err)
	}
	sendRST := false
	r.Complete(sendRST)
}

func tcphandler(handler core.TCPConnHandler) func(*tcp.ForwarderRequest) {
	// The returned function will be run in a fresh goroutine for each incoming socket.
	return func(r *tcp.ForwarderRequest) {
		tcpbridge(handler, r)
	}
}

func MakeTCPBridge(s *stack.Stack, handler core.TCPConnHandler) *tcp.Forwarder {
	return tcp.NewForwarder(s, 0, 10, tcphandler(handler))
}
