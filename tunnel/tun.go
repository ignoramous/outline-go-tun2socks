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

type notifyWriter struct {
	tunWriter io.WriteCloser
	endpoint  *channel.Endpoint
}

// Implements NotifyWriter
func (w *notifyWriter) WriteNotify() {
	packetInfo, ok := w.endpoint.Read()
	if ok {
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

type Endpoint struct {
	*channel.Endpoint
}

// Implements io.Writer.  pkt must be a complete IP packet.
func (e *Endpoint) Write(pkt []byte) (n int, err error) {
	n = len(pkt)
	// NewPacketBuffer takes ownership of the input.  TODO: Avoid copy.
	vv := buffer.NewViewFromBytes(pkt).ToVectorisedView()
	packetBuffer := stack.NewPacketBuffer(stack.PacketBufferOptions{Data: vv})
	//log.Printf("Upstream packet %v", packetBuffer)

	protocol := header.IPv6ProtocolNumber
	if header.IPVersion(pkt) == header.IPv4Version {
		protocol = header.IPv4ProtocolNumber
	}
	e.InjectInbound(protocol, packetBuffer)
	return
}

func NewLink(tunWriter io.WriteCloser) *Endpoint {
	macAddress := tcpip.LinkAddress(string(make([]byte, 6)))
	const pktQueueDepth = 1 // Empirically must be at least 1
	endpoint := channel.New(pktQueueDepth, vpnMtu, macAddress)
	endpoint.AddNotify(&notifyWriter{tunWriter, endpoint})
	// FIXME: What about RemoveNotify?

	return &Endpoint{endpoint}
}
