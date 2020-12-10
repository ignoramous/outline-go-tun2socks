package tunnel

import (
	"io"
	"log"

	_ "github.com/eycorsican/go-tun2socks/common/log/simple" // Import simple log for the side effect of making logs printable.

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/buffer"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

const vpnMtu = 1500

// Implements channel.Notification
type notifyWriter struct {
	tunWriter io.WriteCloser
	link      *channel.Endpoint
}

func (w *notifyWriter) WriteNotify() {
	// Read downstream packet.
	if packetInfo, ok := w.link.Read(); ok {
		// TODO: Avoid copy.
		var data []byte
		for _, view := range packetInfo.Pkt.Views() {
			data = append(data, view...)
		}
		if _, err := w.tunWriter.Write(data); err != nil {
			log.Printf("Downstream packet err=%v", err)
		}
	} else {
		log.Printf("Closing tunWriter")
		w.tunWriter.Close()
	}
}

// InjectionLink provides a LinkEndpoint that supports injection
// (i.e. writing upstream packets) via the Write method.
type InjectionLink interface {
	io.Writer
	stack.LinkEndpoint
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
