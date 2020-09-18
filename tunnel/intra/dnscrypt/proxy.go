package dnscrypt

import (
	"context"
	crypto_rand "crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"runtime"
	"strings"
	"time"

	"github.com/eycorsican/go-tun2socks/common/log"
	"github.com/k-sone/critbitgo"
	stamps "github.com/jedisct1/go-dnsstamps"
	"golang.org/x/crypto/curve25519"
	clocksmith "github.com/jedisct1/go-clocksmith"
)

var undelegatedSet = []string{
	"0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa",
	"0.in-addr.arpa",
	"1",
	"1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa",
	"10.in-addr.arpa",
	"100.100.in-addr.arpa",
	"100.51.198.in-addr.arpa",
	"101.100.in-addr.arpa",
	"102.100.in-addr.arpa",
	"103.100.in-addr.arpa",
	"104.100.in-addr.arpa",
	"105.100.in-addr.arpa",
	"106.100.in-addr.arpa",
	"107.100.in-addr.arpa",
	"108.100.in-addr.arpa",
	"109.100.in-addr.arpa",
	"110.100.in-addr.arpa",
	"111.100.in-addr.arpa",
	"112.100.in-addr.arpa",
	"113.0.203.in-addr.arpa",
	"113.100.in-addr.arpa",
	"114.100.in-addr.arpa",
	"115.100.in-addr.arpa",
	"116.100.in-addr.arpa",
	"117.100.in-addr.arpa",
	"118.100.in-addr.arpa",
	"119.100.in-addr.arpa",
	"120.100.in-addr.arpa",
	"121.100.in-addr.arpa",
	"122.100.in-addr.arpa",
	"123.100.in-addr.arpa",
	"124.100.in-addr.arpa",
	"125.100.in-addr.arpa",
	"126.100.in-addr.arpa",
	"127.100.in-addr.arpa",
	"127.in-addr.arpa",
	"16.172.in-addr.arpa",
	"168.192.in-addr.arpa",
	"17.172.in-addr.arpa",
	"18.172.in-addr.arpa",
	"19.172.in-addr.arpa",
	"2.0.192.in-addr.arpa",
	"20.172.in-addr.arpa",
	"21.172.in-addr.arpa",
	"22.172.in-addr.arpa",
	"23.172.in-addr.arpa",
	"24.172.in-addr.arpa",
	"25.172.in-addr.arpa",
	"254.169.in-addr.arpa",
	"255.255.255.255.in-addr.arpa",
	"26.172.in-addr.arpa",
	"27.172.in-addr.arpa",
	"28.172.in-addr.arpa",
	"29.172.in-addr.arpa",
	"30.172.in-addr.arpa",
	"31.172.in-addr.arpa",
	"64.100.in-addr.arpa",
	"65.100.in-addr.arpa",
	"66.100.in-addr.arpa",
	"67.100.in-addr.arpa",
	"68.100.in-addr.arpa",
	"69.100.in-addr.arpa",
	"70.100.in-addr.arpa",
	"71.100.in-addr.arpa",
	"72.100.in-addr.arpa",
	"73.100.in-addr.arpa",
	"74.100.in-addr.arpa",
	"75.100.in-addr.arpa",
	"76.100.in-addr.arpa",
	"77.100.in-addr.arpa",
	"78.100.in-addr.arpa",
	"79.100.in-addr.arpa",
	"8.b.d.0.1.0.0.2.ip6.arpa",
	"8.e.f.ip6.arpa",
	"80.100.in-addr.arpa",
	"81.100.in-addr.arpa",
	"82.100.in-addr.arpa",
	"83.100.in-addr.arpa",
	"84.100.in-addr.arpa",
	"85.100.in-addr.arpa",
	"86.100.in-addr.arpa",
	"87.100.in-addr.arpa",
	"88.100.in-addr.arpa",
	"89.100.in-addr.arpa",
	"9.e.f.ip6.arpa",
	"90.100.in-addr.arpa",
	"91.100.in-addr.arpa",
	"92.100.in-addr.arpa",
	"93.100.in-addr.arpa",
	"94.100.in-addr.arpa",
	"95.100.in-addr.arpa",
	"96.100.in-addr.arpa",
	"97.100.in-addr.arpa",
	"98.100.in-addr.arpa",
	"99.100.in-addr.arpa",
	"a.e.f.ip6.arpa",
	"airdream",
	"api",
	"b.e.f.ip6.arpa",
	"bbrouter",
	"belkin",
	"bind",
	"blinkap",
	"corp",
	"d.f.ip6.arpa",
	"davolink",
	"dearmyrouter",
	"dhcp",
	"dlink",
	"domain",
	"envoy",
	"example",
	"f.f.ip6.arpa",
	"grp",
	"gw==",
	"home",
	"hub",
	"internal",
	"intra",
	"intranet",
	"invalid",
	"ksyun",
	"lan",
	"loc",
	"local",
	"localdomain",
	"localhost",
	"localnet",
	"modem",
	"mynet",
	"myrouter",
	"novalocal",
	"onion",
	"openstacklocal",
	"priv",
	"private",
	"prv",
	"router",
	"telus",
	"test",
	"totolink",
	"wlan_ap",
	"workgroup",
	"zghjccbob3n0",
}

// Controller represents an dnscrypt session.
type Controller interface {
	// StartProxy starts a dnscrypt proxy, returns number of live-servers and errors if any.
	StartProxy() (int, error)
	// StopProxy stops the dnscrypt proxy
	StopProxy() error
	// Refresh registers servers.
	Refresh() (int, error)
	// AddServers adds new dns-crypt resolvers given csv-separated list of "unqiue-id:dns-stamp"
	AddServers(string) (int, error)
	// RemoveServers removes existing dns-crypt resolvers given csv-separated list of "unqiue-id"s
	RemoveServers(string) (int, error)
	// AddRoutes adds new dns-crypt relay given csv-separated list of "dns-stamp"
	AddRoutes(string) (int, error)
	// RemoveRoutes removes existing dns-crypt relays given csv-separated list of "dns-stamp"
	RemoveRoutes(string) (int, error)
}

type Proxy struct {
	Controller
	undelegatedSet				   *critbitgo.Trie
	proxyPublicKey                 [32]byte
	proxySecretKey                 [32]byte
	serversInfo                    ServersInfo
	timeout                        time.Duration
	certRefreshDelay               time.Duration
	certRefreshDelayAfterFailure   time.Duration
	certIgnoreTimestamp            bool
	mainProto                      string
	registeredServers              []RegisteredServer
	registeredRelays               []RegisteredServer
	routes                         []string
	quit						   chan bool
	listener					   Listener
	sigterm						   context.CancelFunc
}

func (proxy *Proxy) exchangeWithTCPServer(serverInfo *ServerInfo, sharedKey *[32]byte, encryptedQuery []byte, clientNonce []byte) ([]byte, error) {
	upstreamAddr := serverInfo.TCPAddr
	if serverInfo.RelayTCPAddr != nil {
		upstreamAddr = serverInfo.RelayTCPAddr
	}
	var pc net.Conn
	pc, err := net.DialTCP("tcp", nil, upstreamAddr)
	if err != nil {
		log.Errorf("failed to dial %s upstream because %v", serverInfo.String(), err)
		return nil, err
	}
	defer pc.Close()
	if err := pc.SetDeadline(time.Now().Add(serverInfo.Timeout)); err != nil {
		log.Errorf("failed to set timeout because %v", err)
		return nil, err
	}
	if serverInfo.RelayTCPAddr != nil {
		proxy.prepareForRelay(serverInfo.TCPAddr.IP, serverInfo.TCPAddr.Port, &encryptedQuery)
	}
	encryptedQuery, err = PrefixWithSize(encryptedQuery)
	if err != nil {
		log.Errorf("failed prefix(encrypted-query) from %s because %v", serverInfo.String(), err)
		return nil, err
	}
	if _, err := pc.Write(encryptedQuery); err != nil {
		log.Errorf("failed to write to remote-addr at %s because %v", serverInfo.String(), err)
		return nil, err
	}
	encryptedResponse, err := ReadPrefixed(&pc)
	if err != nil {
		log.Errorf("failed to read(encrypted-response) from %s because %v", serverInfo.String(), err)
		return nil, err
	}
	return proxy.Decrypt(serverInfo, sharedKey, encryptedResponse, clientNonce)
}

func (proxy *Proxy) prepareForRelay(ip net.IP, port int, encryptedQuery *[]byte) {
	anonymizedDNSHeader := []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00}
	relayedQuery := append(anonymizedDNSHeader, ip.To16()...)
	var tmp [2]byte
	binary.BigEndian.PutUint16(tmp[0:2], uint16(port))
	relayedQuery = append(relayedQuery, tmp[:]...)
	relayedQuery = append(relayedQuery, *encryptedQuery...)
	*encryptedQuery = relayedQuery
}

func (proxy *Proxy) query(packet []byte, truncate bool) (response []byte, serverInfo *ServerInfo, qerr error) {
	if len(packet) < MinDNSPacketSize {
		log.Warnf("DNS query size too short, cannot process dns-crypt query.")
		qerr = &dnscryptError{BadQuery, fmt.Errorf("dns-crypt query size too short")}
		return
	}

	intercept := NewIntercept(proxy.undelegatedSet)
	// serverName := "-"
	// needsEDNS0Padding = (serverInfo.Proto == stamps.StampProtoTypeDoH || serverInfo.Proto == stamps.StampProtoTypeTLS)
	needsEDNS0Padding := false

	query, err := intercept.HandleRequest(packet, needsEDNS0Padding)

	if (err != nil || intercept.state.action == ActionDrop) {
		log.Errorf("ActionDrop or err on request %w.", err)
		qerr = &dnscryptError{BadQuery, err}
		return
	}
	if len(query) < MinDNSPacketSize {
		log.Errorf("DNS query size too short, cannot post-process dns-crypt query.")
		qerr = &dnscryptError{BadQuery, err}
		return
	}
	if len(query) > MaxDNSPacketSize {
		log.Errorf("DNS query size too large, cannot process dns-crypt query.")
		qerr = &dnscryptError{BadQuery, err}
		return
	}
	state := intercept.state
	if state.response != nil {
		response, err = state.response.PackBuffer(response)
		if (err != nil) {
			log.Warnf("sending intercepted response failed %w", err)
			qerr = &dnscryptError{BadResponse, err}
		}
		return
	}

	serverInfo = proxy.serversInfo.getOne()

	if serverInfo == nil {
		log.Warnf("ServerInfo not found, cannot process dns-crypt query")
		qerr = &dnscryptError{InternalError, err}
		return
	}

	if serverInfo.Proto == stamps.StampProtoTypeDNSCrypt {
		sharedKey, encryptedQuery, clientNonce, err := proxy.Encrypt(serverInfo, query, proxy.mainProto)

		if err != nil {
			log.Warnf("Encryption failure with dns-crypt query to %s.", serverInfo.String())
			qerr = &dnscryptError{InternalError, err}
			return
		}

		response, err = proxy.exchangeWithTCPServer(serverInfo, sharedKey, encryptedQuery, clientNonce)

		if err != nil {
			log.Warnf("dns crypt query exchange with %s failed: %v", serverInfo.String(), err)
			qerr = &dnscryptError{SendFailed, err}
			return
		}
	} else if serverInfo.Proto == stamps.StampProtoTypeDoH {
		// FIXME: implement
		log.Errorf("Unsupported dns-crypt transport protocol")
		qerr = &dnscryptError{SendFailed, fmt.Errorf("doh not supported with dns-crypt proxy")}
		return
	} else {
		log.Errorf("Unsupported dns-crypt transport protocol")
		qerr = &dnscryptError{Error, fmt.Errorf("dns-crypt: unknown protocol")}
		return
	}

	if len(response) < MinDNSPacketSize || len(response) > MaxDNSPacketSize {
		log.Errorf("response packet size from %s too small or too large", serverInfo.String())
		qerr = &dnscryptError{BadResponse, fmt.Errorf("response packet size too small or too big")}
		return
	}

	response, err = intercept.HandleResponse(response, truncate)

	if (err != nil) {
		log.Errorf("failed to intercept %s response %w", serverInfo.String(), err)
		qerr = &dnscryptError{BadResponse, err}
	}

	return
}

// HandleUDP handles incoming udp connection speaking plain old DNS
func HandleUDP(proxy *Proxy, data []byte) (response []byte, err error) {
	if (proxy == nil) {
		return nil, fmt.Errorf("dns-crypt proxy not set")
	}

	var s *ServerInfo

	before := time.Now()
	response, s, err = proxy.query(data, true)
	after := time.Now()

	if proxy.listener != nil {
		latency := after.Sub(before)
		status := Complete

		var resolver string
		var relay string
		if s != nil {
			resolver = s.TCPAddr.IP.String()
			if (s.RelayTCPAddr != nil) {
				relay = s.RelayTCPAddr.IP.String()
			}
		}

		var qerr *dnscryptError
		if errors.As(err, &qerr) {
			status = qerr.status
		}

		proxy.listener.OnDNSCryptResponse(&Summary{
			Latency:    	latency.Seconds(),
			Query:      	data,
			Response:   	response,
			Server:     	resolver,
			RelayServer:    relay,
			Status: 		status,
		})
	}

	return response, err
}

func (proxy *Proxy) forward(conn net.Conn) (q []byte, response []byte, serverInfo *ServerInfo, err error) {

	// Unlike Intra's handling of DoH (?), DNSCrypt strictly closes
	// connection after a single read-response cycle.
	if err = conn.SetDeadline(time.Now().Add(proxy.timeout)); err != nil {
		q, err = ReadPrefixed(&conn)
	}
	if err != nil {
		log.Errorf("could not read dns query %v", err)
		return
	}

	response, serverInfo, err = proxy.query(q, false)

	if err != nil {
		log.Errorf("failed forwarding dnscrypt query %w", err)
		return
	}
	response, err = PrefixWithSize(response)
	if (err != nil) {
		log.Errorf("failed reading answer for dnscrypt query %w", err)
	}
	return
}

// HandleTCP handles incoming tcp connection speaking plain old DNS
func HandleTCP(proxy *Proxy, conn net.Conn) {
	defer conn.Close()

	if (proxy == nil) {
		log.Errorf("dns-crypt proxy not set")
		return
	}

	var err error
	var response []byte
	var query []byte
	var s *ServerInfo

	before := time.Now()
	query, response, s, err = proxy.forward(conn)
	after := time.Now()

	if proxy.listener != nil {
		latency := after.Sub(before)
		status := Complete

		var resolver string
		var relay string
		if s != nil {
			resolver = s.TCPAddr.IP.String()
			relay = s.RelayTCPAddr.IP.String()
		}

		var qerr *dnscryptError
		if errors.As(err, &qerr) {
			status = qerr.status
		}

		proxy.listener.OnDNSCryptResponse(&Summary{
			Latency:    	latency.Seconds(),
			Query:      	query,
			Response:   	response,
			Server:     	resolver,
			RelayServer:    relay,
			Status: 		status,
		})
	}

	/*number of byte, err*/
	_, err = conn.Write(response)
	if err != nil {
		log.Errorf("failed writing dns response: %w", err)
	}
}

// Refresh re-registers servers
func (proxy *Proxy) Refresh() (int, error) {
	for _, registeredServer := range proxy.registeredServers {
		proxy.serversInfo.registerServer(registeredServer.name, registeredServer.stamp)
	}
	liveServers, err := proxy.serversInfo.refresh(proxy)
	if liveServers > 0 {
		proxy.certIgnoreTimestamp = false
	} else if err != nil {
		// ignore error if live-servers are around
		return 0, err
	}
	return liveServers, nil;
}

// StartProxy fetches server-list and starts a dnscrypt stub resolver
func (proxy *Proxy) StartProxy() (int, error) {
	ctx, cancel := context.WithCancel(context.Background())
	proxy.sigterm = cancel
	if _, err := crypto_rand.Read(proxy.proxySecretKey[:]); err != nil {
		return 0, err
	}
	curve25519.ScalarBaseMult(&proxy.proxyPublicKey, &proxy.proxySecretKey)
	liveServers, err := proxy.Refresh()
	if len(proxy.serversInfo.registeredServers) > 0 {
		go func(ctx context.Context) {
			for {
				select {
				case <-ctx.Done():
					log.Infof("cert refresh go rountine stopped.")
					return
				default:
					delay := proxy.certRefreshDelay
					if liveServers == 0 {
						delay = proxy.certRefreshDelayAfterFailure
					}
					clocksmith.Sleep(delay)
					liveServers, _ = proxy.serversInfo.refresh(proxy)
					if liveServers > 0 {
						proxy.certIgnoreTimestamp = false
					}
					runtime.GC()
				}
			}
		}(ctx)
	}
	return liveServers, err
}

func (proxy *Proxy) StopProxy() error {
	if (proxy.sigterm != nil) {
		proxy.sigterm()
	}
	return nil
}

// AddRoutes set anonymous dnscrypt relay routes
func (proxy *Proxy) AddRoutes(routescsv string) (int, error) {
	if (len(routescsv) <= 0) {
		return 0, fmt.Errorf("specify atleast one dns-crypt route")
	}
	r := findUnique(proxy.routes, strings.Split(routescsv, ","))
	proxy.routes = append(proxy.routes, r...)
	return len(r), nil
}

func (proxy *Proxy) RemoveRoutes(routescsv string) (int, error) {
	if (len(routescsv) <= 0) {
		return 0, fmt.Errorf("specify atleast one dns-crypt route")
	}
	rm := strings.Split(routescsv, ",")
	l := len(proxy.routes)
	proxy.routes = findUnique(proxy.routes, rm)
	return l - len(proxy.routes), nil
}

func (proxy *Proxy) RemoveServers(servernamescsv string) (int, error) {
	if (len(servernamescsv) <= 0) {
		return 0, fmt.Errorf("specify at least one dns-crypt resolver endpoint")
	}

	servernames := strings.Split(servernamescsv, ",")
	var c int
	for _, name := range(servernames) {
		if (len(name) == 0) {
			continue
		}
		// TODO: handle err
		n, _ := proxy.serversInfo.unregisterServer(name)
		c = c + n
	}
	return c, nil
}

// AddServers registers additional dnscrypt servers
func (proxy *Proxy) AddServers(serverscsv string) (int, error) {
	if (len(serverscsv) <= 0) {
		return 0, fmt.Errorf("specify at least one dns-crypt resolver endpoint")
	}

	servers := strings.Split(serverscsv, ",")
	var registeredServers []RegisteredServer
	for _, serverStampPair := range servers {
		if len(serverStampPair) == 0 {
			return 0, fmt.Errorf("Missing stamp for the stamp [%s] definition", serverStampPair)
		}
		serverStamp := strings.Split(serverStampPair, ":")
		stamp, err := stamps.NewServerStampFromString(serverStamp[1])
		if err != nil {
			return 0, fmt.Errorf("Stamp error for the stamp [%s] definition: [%v]", serverStampPair, err)
		}
		if (stamp.Proto == stamps.StampProtoTypeDoH) {
			// TODO: Implement doh
			return 0, fmt.Errorf("DoH with DNSCrypt client not supported", serverStamp)
		}
		registeredServers = append(registeredServers, RegisteredServer{name: serverStamp[0], stamp: stamp})
	}
	proxy.registeredServers = append(proxy.registeredServers, registeredServers...)
	return len(registeredServers), nil
}

// NewProxy creates a dnscrypt proxy
func NewProxy(l Listener) *Proxy {
	suffixes := critbitgo.NewTrie()
	for _, line := range undelegatedSet {
		pattern := StringReverse(line)
		suffixes.Insert([]byte(pattern), true)
	}
	return &Proxy{
		routes:							nil,
		registeredServers:				nil,
		undelegatedSet:					suffixes,
		certRefreshDelay:				time.Duration(240) * time.Minute,
		certRefreshDelayAfterFailure:	time.Duration(10 * time.Second),
		certIgnoreTimestamp:		 	false,
		timeout:	 					time.Duration(20000) * time.Millisecond,
		mainProto: 						"tcp",
		serversInfo: 					NewServersInfo(),
		listener:						l,
	}
}