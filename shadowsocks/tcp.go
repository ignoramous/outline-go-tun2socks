package shadowsocks

import (
	"log"
	"net"

	"github.com/Jigsaw-Code/outline-go-tun2socks/core"
	onet "github.com/Jigsaw-Code/outline-ss-server/net"
	"github.com/Jigsaw-Code/outline-ss-server/shadowsocks"
)

type tcpHandler struct {
	client shadowsocks.Client
}

// NewTCPHandler returns a Shadowsocks TCP connection handler.
//
// `host` is the hostname of the Shadowsocks proxy server.
// `port` is the port of the Shadowsocks proxy server.
// `password` is password used to authenticate to the server.
// `cipher` is the encryption cipher of the Shadowsocks proxy.
func NewTCPHandler(host string, port int, password, cipher string) core.TCPConnHandler {
	client, err := shadowsocks.NewClient(host, port, password, cipher)
	if err != nil {
		log.Printf("Error creating shadowsocks client: %v\n", err)
		return nil
	}
	return &tcpHandler{client}
}

func (h *tcpHandler) Handle(conn net.Conn, target *net.TCPAddr) error {
	proxyConn, err := h.client.DialTCP(nil, target.String())
	if err != nil {
		return err
	}
	go onet.Relay(conn.(onet.DuplexConn), proxyConn)
	return nil
}
