package tunnel

import (
	"errors"
	"io"
	"net"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/buffer"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/waiter"
)

type tcplike interface {
	io.ReadWriteCloser
	CloseRead() error
	CloseWrite() error
}

func tcpupload(endpoint tcpip.Endpoint, tcpconn tcplike, q *waiter.Queue) {
	waitEntry, notifyCh := waiter.NewChannelEntry(nil)
	q.EventRegister(&waitEntry, waiter.EventIn)
	for {
		v, _, err := endpoint.Read(nil)
		if err != nil {
			if err == tcpip.ErrWouldBlock {
				<-notifyCh
				continue
			}

			break
		}

		if _, err := tcpconn.Write(v); err != nil {
			break
		}
	}
	q.EventUnregister(&waitEntry)
	tcpconn.CloseWrite()
	endpoint.Shutdown(tcpip.ShutdownRead)
}

func tcpdownload(endpoint tcpip.Endpoint, tcpconn tcplike, q *waiter.Queue) {
	waitEntry, notifyCh := waiter.NewChannelEntry(nil)
	q.EventRegister(&waitEntry, waiter.EventOut)
	for {
		v := buffer.NewView(4096)
		n, err := tcpconn.Read(v)
		if err != nil {
			break
		}
		v.CapLength(n)
		for {
			n, _, err := endpoint.Write(tcpip.SlicePayload(v), tcpip.WriteOptions{})
			v.TrimFront(int(n))
			if err == tcpip.ErrWouldBlock || err == nil && len(v) > 0 {
				<-notifyCh
				continue
			} else if err != nil || len(v) == 0 {
				break
			}

		}
	}
	q.EventUnregister(&waitEntry)
	endpoint.Shutdown(tcpip.ShutdownWrite)
	tcpconn.CloseRead()
}

func tcpbridge(dialer *net.Dialer, r *tcp.ForwarderRequest) {
	id := r.ID()
	remoteAddr := net.TCPAddr{
		IP:   []byte(id.RemoteAddress),
		Port: int(id.RemotePort),
	}
	conn, err := dialer.Dial(remoteAddr.Network(), remoteAddr.String())
	if err != nil {
		timeout := false
		var neterr net.Error
		if errors.As(err, neterr) {
			timeout = neterr.Timeout()
		}
		// If the error is a timeout, then we never received any packets from
		// the remote address.  We match this behavior by abandoning the
		// connection without sending a RST in this case.
		sendRST := !timeout
		r.Complete(sendRST)
		return
	}
	tcpconn := conn.(tcplike)
	var q waiter.Queue
	endpoint, stackerr := r.CreateEndpoint(&q) // SYNACK
	r.Complete(false)                          // No RST
	if stackerr != nil {
		tcpconn.Close()
		return
	}

	go tcpupload(endpoint, tcpconn, &q)
	tcpdownload(endpoint, tcpconn, &q)

	endpoint.Close()
	tcpconn.Close()
}

func tcphandler(dialer *net.Dialer) func(*tcp.ForwarderRequest) {
	return func(r *tcp.ForwarderRequest) {
		go tcpbridge(dialer, r)
	}
}
