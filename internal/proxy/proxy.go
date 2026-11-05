package proxy

import (
	"fmt"
	"math/rand/v2"
	"net"
	"os"
	"regexp"
	"sync"
	"time"

	"github.com/jhead/phantom/internal/clientmap"
	"github.com/jhead/phantom/internal/proto"
	"github.com/rs/zerolog/log"
	"github.com/tevino/abool"

	reuse "github.com/libp2p/go-reuseport"
)

// testKnobsMu guards the tunable duration knobs (serverReadDelay) that
// integration tests compress (milliseconds) to exercise production
// windows. Workers read them concurrently, hence the lock.
var testKnobsMu sync.Mutex

const maxMTU = 1472

var idleCheckInterval = 5 * time.Second

// errorBackoff paces retries in readLoop after a transient processing
// error, guarding against a hot spin if the listener ever returns without
// blocking (e.g., closed concurrently). The normal path — a blocking
// ReadFrom — is unaffected.
var errorBackoff = 100 * time.Millisecond

// serverReadDelay caps how long a pending read from the server may sit
// before it is released. Promoted from an inline literal so integration
// tests can compress it (milliseconds instead of 5s).
var serverReadDelay = 5 * time.Second

// setServerReadDelay updates the knob under the lock (test hook).
func setServerReadDelay(d time.Duration) {
	testKnobsMu.Lock()
	serverReadDelay = d
	testKnobsMu.Unlock()
}

type ProxyServer struct {
	bindAddress         *net.UDPAddr
	boundPort           uint16
	remoteServerAddress *net.UDPAddr
	pingServer          net.PacketConn
	pingServerV6        net.PacketConn
	server              *net.UDPConn
	clientMap           *clientmap.ClientMap
	prefs               ProxyPrefs
	dead                *abool.AtomicBool
	serverOffline       *abool.AtomicBool
}

type ProxyPrefs struct {
	BindAddress  string
	BindPort     uint16
	RemoteServer string
	IdleTimeout  time.Duration
	EnableIPv6   bool
	RemovePorts  bool
	NumWorkers   uint
	// PingPort/PingPortV6 are the ports consoles broadcast pings to.
	// Zero selects an ephemeral port (useful for tests); the default
	// deployment relies on the conventional 19132/19133 (see
	// Start()).
	PingPort   uint16
	PingPortV6 uint16
}

// serverID is a unique per-instance identifier advertised to clients; it must
// be freshly derived on every phantom start so restarting doesn't confuse
// clients that remember the previous ID. Safe under concurrent use:
// math/rand/v2's top-level functions are thread-safe. (62-bit range —
// collision probability is negligible, and negative values are impossible
// unlike rand.Int64().)
var serverID = rand.Int64N(1 << 62)
var offlineErrorRegex = regexp.MustCompile("(timeout)|(connection refused)")

func New(prefs ProxyPrefs) (*ProxyServer, error) {
	bindPort := prefs.BindPort

	// Randomize port if not provided
	if bindPort == 0 {
		bindPort = uint16(rand.IntN(14000)) + 50000
	}

	// Format full bind address with port
	prefs.BindAddress = fmt.Sprintf("%s:%d", prefs.BindAddress, bindPort)

	bindAddress, err := net.ResolveUDPAddr("udp", prefs.BindAddress)
	if err != nil {
		return nil, fmt.Errorf("Invalid bind address: %s", err)
	}

	remoteServerAddress, err := net.ResolveUDPAddr("udp", prefs.RemoteServer)
	if err != nil {
		return nil, fmt.Errorf("Invalid server address: %s", err)
	}

	// Reject a missing port outright: a remote address with port 0 would
	// silently "connect" to an unreachable address (UDP has no handshake,
	// so this would never error), and phantom would run degraded without
	// saying so.
	if remoteServerAddress.Port == 0 {
		return nil, fmt.Errorf("invalid server address %q: no port specified (use host:port, e.g. 192.168.1.20:19132)", prefs.RemoteServer)
	}

	return &ProxyServer{
		bindAddress,
		bindPort,
		remoteServerAddress,
		nil,
		nil,
		nil,
		clientmap.New(prefs.IdleTimeout, idleCheckInterval),
		prefs,
		abool.New(),
		abool.New(),
	}, nil
}

func (proxy *ProxyServer) Start() error {
	// Bind to the console ping port on all addresses to receive broadcasted pings.
	// Sets SO_REUSEADDR et al to support multiple instances of phantom.
	// Port 0 in prefs keeps the conventional 19132 (deployment-default);
	// a non-zero port is honoured as-is (tests use picked ports).
	pingPort := proxy.prefs.PingPort
	if pingPort == 0 {
		pingPort = 19132
	}
	log.Info().Msgf("Binding ping server to port %d", pingPort)
	if pingServer, err := reuse.ListenPacket("udp4", fmt.Sprintf(":%d", pingPort)); err == nil {
		proxy.pingServer = pingServer

		// Start proxying ping packets from the broadcast listener
		go proxy.readLoop(proxy.pingServer)
	} else {
		// Bind failed
		return err
	}

	// Minecraft also broadcasts pings to the IPv6 console port
	// (19133 by default); EnableIPv6 opts into it.
	if proxy.prefs.EnableIPv6 {
		v6Port := proxy.prefs.PingPortV6
		if v6Port == 0 {
			v6Port = 19133
		}
		log.Info().Msgf("Binding IPv6 ping server to port %d", v6Port)
		if pingServerV6, err := reuse.ListenPacket("udp6", fmt.Sprintf(":%d", v6Port)); err == nil {
			proxy.pingServerV6 = pingServerV6

			// Start proxying ping packets from the broadcast listener
			go proxy.readLoop(proxy.pingServerV6)
		} else {
			// IPv6 Bind failed
			log.Warn().Msgf("Failed to bind IPv6 ping listener: %v", err)
		}
	}

	network := "udp4"
	if proxy.prefs.EnableIPv6 {
		network = "udp"
	}

	// Bind to specified UDP addr and port to receive data from Minecraft clients
	log.Info().Msgf("Binding proxy server to: %v", proxy.bindAddress)
	if server, err := reuse.ListenPacket(network, proxy.bindAddress.String()); err == nil {
		// a safe cast, I promise
		proxy.server = server.(*net.UDPConn)
	} else {
		// Don't leak the ping listeners (and their readLoop goroutines)
		// that were already started — shut them down on this failure path.
		proxy.shutdownListeners()
		return err
	}

	log.Info().Msgf("Proxy server listening!")
	log.Info().Msgf("Once your console pings phantom, you should see replies below.")

	// Start processing everything else using the proxy listener
	proxy.startWorkers(proxy.server)

	return nil
}

func (proxy *ProxyServer) Close() {
	log.Info().Msg("Stopping proxy server")

	// Shut down UDP listeners (nil-guarded: Start may fail before every
	// listener is assigned, and Close is still called on interrupt)
	if proxy.server != nil {
		proxy.server.Close()
	}
	if proxy.pingServer != nil {
		proxy.pingServer.Close()
	}
	if proxy.pingServerV6 != nil {
		proxy.pingServerV6.Close()
	}

	// Close all connections
	proxy.clientMap.Close()

	// Stop loops
	proxy.dead.Set()
}

// shutdownListeners reverses Start's partial-setup on the failure path so
// callers don't leak already-bound listeners or the readLoop goroutines
// attached to them. Setting dead makes the in-flight readLoops exit.
func (proxy *ProxyServer) shutdownListeners() {
	proxy.dead.Set()
	if proxy.pingServerV6 != nil {
		proxy.pingServerV6.Close()
		proxy.pingServerV6 = nil
	}
	if proxy.pingServer != nil {
		proxy.pingServer.Close()
		proxy.pingServer = nil
	}
}

func (proxy *ProxyServer) startWorkers(listener net.PacketConn) {
	// Clamp to at least one worker: with NumWorkers == 0, zero workers
	// would be launched and Start would return a zombie proxy that
	// listens but never forwards packets.
	numWorkers := proxy.prefs.NumWorkers
	if numWorkers == 0 {
		numWorkers = 1
	}

	log.Info().Msgf("Starting %d workers", numWorkers)

	for i := uint(0); i < numWorkers; i++ {
		if i < numWorkers-1 {
			go proxy.readLoop(listener)
		} else {
			// Last worker runs in the current goroutine, so Start()
			// blocks until the proxy is shut down.
			proxy.readLoop(listener)
		}
	}
}

// Continually reads data from the provided listener and passes it to
// processDataFromClients until the ProxyServer has been closed.
func (proxy *ProxyServer) readLoop(listener net.PacketConn) {
	log.Info().Msgf("Listener starting up: %s", listener.LocalAddr())

	packetBuffer := make([]byte, maxMTU)

	for !proxy.dead.IsSet() {
		err := proxy.processDataFromClients(listener, packetBuffer)
		if err != nil {
			// Back off on error to avoid hot-spinning on a sustained
			// failure (e.g. a flap in remote connection establishment).
			// The happy path (err == nil) is unaffected — no sleep.
			log.Warn().Msgf("Error while processing client data: %s", err)
			time.Sleep(errorBackoff)
		}
	}

	log.Info().Msgf("Listener shut down: %s", listener.LocalAddr())
}

// Inspects an incoming UDP packet, looking up the client in our connection
// map, lazily creating a new connection to the remote server when necessary,
// then forwarding the data to that remote connection.
//
// When a new client connects, an additional goroutine is created to read
// data from the server and send it back to the client.
func (proxy *ProxyServer) processDataFromClients(listener net.PacketConn, packetBuffer []byte) error {
	// Read the next packet from the client
	read, client, _ := listener.ReadFrom(packetBuffer)
	if read <= 0 {
		return nil
	}

	data := packetBuffer[:read]
	log.Trace().Msgf("client recv: %v", data)

	// Handler triggered when a new client connects and we create a new connetion to the remote server
	onNewConnection := func(newServerConn *net.UDPConn) {
		log.Info().Msgf("New connection from client %s -> %s", client.String(), listener.LocalAddr())
		proxy.processDataFromServer(newServerConn, client)
	}

	serverConn, err := proxy.clientMap.Get(
		client,
		proxy.remoteServerAddress,
		onNewConnection,
	)

	if err != nil {
		return err
	}

	// Give the server up to serverReadDelay to respond to whatever we sent
	// before the read is considered stalled.
	testKnobsMu.Lock()
	delay := serverReadDelay
	testKnobsMu.Unlock()
	_ = serverConn.SetReadDeadline(time.Now().Add(delay))

	if packetID := data[0]; packetID == proto.UnconnectedPingID {
		log.Info().Msgf("Received LAN ping from client: %s", client.String())

		if proxy.serverOffline.IsSet() {
			replyBuffer := proto.OfflinePong
			replyBytes := proxy.rewriteUnconnectedPong(replyBuffer.Bytes())

			proxy.server.WriteTo(replyBytes, client)
			log.Info().Msgf("Sent server offline pong to client: %v", client.String())
		}

		// Pass ping through to server even if it's offline
	}

	// Write packet from client to server
	_, err = serverConn.Write(data)
	return err
}

// Proxies packets sent by the server to us for a specific Minecraft client back to
// that client's UDP connection.
func (proxy *ProxyServer) processDataFromServer(remoteConn *net.UDPConn, client net.Addr) {
	buffer := make([]byte, maxMTU)

	for !proxy.dead.IsSet() {
		// Read the next packet from the server
		read, _, err := remoteConn.ReadFrom(buffer)

		// Remove read timeout, server responded
		_ = remoteConn.SetReadDeadline(time.Time{})

		// Read error
		if err != nil {
			// A read timeout is TRANIENT: the shared conn's read deadline is
			// advanced by the worker on every forwarded client packet (see
			// SetReadDeadline below in processDataFromClients). A healthy but
			// momentarily silent server triggers it (UDPs do not heartbeat),
			// so it must not tear the connection down or mark the server
			// offline. Reset the deadline (block infinitely again) and keep
			// waiting.
			if os.IsTimeout(err) {
				log.Warn().Msgf("Server read timed out (transient); keeping connection: %v", err)
				_ = remoteConn.SetReadDeadline(time.Time{})
				continue
			}

			log.Warn().Msgf("%v", err)

			// Mark offline if the failure indicates a connectivity loss
			// (deduplicated: log warn only on the false->true transition)
			offlineError := offlineErrorRegex.MatchString(err.Error())
			if offlineError && proxy.serverOffline.SetToIf(false, true) {
				log.Warn().Msg("Server seems to be offline :(")
				log.Warn().Msg("We'll keep trying to connect...")
			}

			break
		}

		// Empty read
		if read < 1 {
			continue
		}

		// Clear the flag if the server came back online; log only on the
		// true->false transition (i.e., we recover from the offline state)
		if proxy.serverOffline.SetToIf(true, false) {
			log.Info().Msgf("Server is back online!")
		}

		// Resize data to byte count from 'read'
		data := buffer[:read]
		log.Trace().Msgf("server recv: %v", data)

		// Rewrite Unconnected Pong packets
		if packetID := data[0]; packetID == proto.UnconnectedPongID {
			data = proxy.rewriteUnconnectedPong(data)
			log.Info().Msgf("Sent LAN pong to client: %v", client.String())
		}

		proxy.server.WriteTo(data, client)
	}

	proxy.clientMap.Delete(client)
}

func (proxy *ProxyServer) rewriteUnconnectedPong(data []byte) []byte {
	log.Debug().Msgf("Received Unconnected Pong from server: %v", data)

	if packet, err := proto.ReadUnconnectedPing(data); err == nil {
		// Overwrite the server ID with one unique to this phantom instance.
		// If we don't do this, the client will get confused if you restart phantom.
		packet.Pong.ServerID = fmt.Sprintf("%d", serverID)

		// Overwrite port numbers sent back from server (if any)
		if packet.Pong.Port4 != "" && !proxy.prefs.RemovePorts {
			packet.Pong.Port4 = fmt.Sprintf("%d", proxy.boundPort)
			packet.Pong.Port6 = packet.Pong.Port4
		} else if proxy.prefs.RemovePorts {
			packet.Pong.Port4 = ""
			packet.Pong.Port6 = ""
		}

		packetBuffer := packet.Build()
		log.Debug().Msgf("Unconnected Pong: %v", packet)
		return packetBuffer.Bytes()
	} else {
		log.Warn().Msgf("Failed to rewrite pong: %v", err)
	}

	return data
}
