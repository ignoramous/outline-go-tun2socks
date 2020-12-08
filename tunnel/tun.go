package tunnel

import (
	"io"
	"log"

	"github.com/Jigsaw-Code/outline-ss-server/slicepool"
	_ "github.com/eycorsican/go-tun2socks/common/log/simple" // Import simple log for the side effect of making logs printable.
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/buffer"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

const vpnMtu = 1500

var pool = slicepool.MakePool(vpnMtu)

// Implements channel.Notification
type notifyWriter struct {
	tunWriter io.WriteCloser
	link      *channel.Endpoint
}

func (w *notifyWriter) WriteNotify() {
	// Read downstream packet.
	if packetInfo, ok := w.link.Read(); ok {
		// Combine headers and body into a single write to the TUN device.
		lazySlice := pool.LazySlice()
		buf := lazySlice.Acquire()[:0]
		for _, view := range packetInfo.Pkt.Views() {
			buf = append(buf, view...)
		}
		if _, err := w.tunWriter.Write(buf); err != nil {
			log.Printf("Downstream packet err=%v", err)
		}
		lazySlice.Release()
	} else {
		log.Printf("Closing tunWriter")
		w.tunWriter.Close()
	}
}

// InjectionLink provides a LinkEndpoint that supports injection
// (i.e. writing upstream packets) via the Write method.
type InjectionLink interface {
	stack.LinkEndpoint
	io.Writer
}

// Adds injection support to a channel-based link endpoint.
type injector struct {
	*channel.Endpoint
}

// Implements io.Writer.  pkt must be a complete upstream IP packet.
func (e injector) Write(pkt []byte) (int, error) {
	// NewPacketBuffer takes ownership of its input.  TODO: Avoid copy.
	vv := buffer.NewViewFromBytes(pkt).ToVectorisedView()
	packetBuffer := stack.NewPacketBuffer(stack.PacketBufferOptions{Data: vv})

	protocol := header.IPv6ProtocolNumber
	if header.IPVersion(pkt) == header.IPv4Version {
		protocol = header.IPv4ProtocolNumber
	}
	e.InjectInbound(protocol, packetBuffer)
	return len(pkt), nil
}

// NewLink wraps `tunWriter` (which provides downstream Write) into a
// stack.LinkEndpoint with a method for upstream Writes.
func NewLink(tunWriter io.WriteCloser) InjectionLink {
	macAddress := tcpip.LinkAddress(string(make([]byte, 6)))
	const pktQueueDepth = 1 // Empirically must be at least 1
	link := channel.New(pktQueueDepth, vpnMtu, macAddress)
	link.AddNotify(&notifyWriter{tunWriter, link})
	return injector{link}
}
