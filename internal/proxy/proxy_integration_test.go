package proxy

import (
	"bytes"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/jhead/phantom/internal/proto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// -------------------------------------------------------------------------
// Integration test harness: a fake Bedrock server and a test client, both
// talking real UDP to a real proxy (started via Start()). White-box:
// internal/proxy is the same package, so unexported fields are readable.
// -------------------------------------------------------------------------

var fakeMagic = []byte{
	0x00, 0xff, 0xff, 0x00,
	0xfe, 0xfe, 0xfe, 0xfe,
	0xfd, 0xfd, 0xfd, 0xfd,
	0x12, 0x34, 0x56, 0x78,
}

// fakeServer simulates a Bedrock server on real UDP: it decodes the
// incoming pings with the project's own proto codec and replies with a
// canned pong. Its replies echo the ping's header fields, mirroring the
// racknet contract.
type fakeServer struct {
	mu    sync.Mutex
	addr  *net.UDPAddr
	lc    *net.UDPConn
	got   map[string]int
	total int
	reply bool
}

func startFakeServer(t *testing.T, port int) *fakeServer {
	t.Helper()
	a, err := net.ResolveUDPAddr("udp", fmt.Sprintf("127.0.0.1:%d", port))
	require.NoError(t, err)
	fs := &fakeServer{addr: a, got: map[string]int{}, reply: true}
	require.NoError(t, fs.listen())
	t.Cleanup(fs.stop)
	return fs
}

func (fs *fakeServer) listen() error {
	lc, err := net.ListenUDP("udp", fs.addr)
	if err != nil {
		return err
	}
	fs.lc = lc
	go fs.loop(lc)
	return nil
}

func (fs *fakeServer) loop(lc *net.UDPConn) {
	buf := make([]byte, 4096)
	for {
		n, src, err := lc.ReadFrom(buf)
		if err != nil {
			return
		}
		fs.mu.Lock()
		fs.total++
		fs.got[src.(*net.UDPAddr).String()]++
		reply := fs.reply
		hasPayload := n > 0 && buf[0] == proto.UnconnectedPingID && reply
		var ping *proto.UnconnectedPing
		if hasPayload {
			pk, derr := proto.ReadUnconnectedPing(buf[:n])
			if derr == nil {
				ping = pk
			}
		}
		fs.mu.Unlock()

		if ping != nil {
			pong := proto.UnconnectedPing{
				PingTime: ping.PingTime,
				ID:       ping.ID,
				Magic:    ping.Magic,
				Pong: proto.PongData{
					Edition:         "MCPE",
					MOTD:            "fake motd",
					ProtocolVersion: "409",
					Version:         "1.19.80",
					Players:         "1",
					MaxPlayers:      "10",
					ServerID:        "98765",
					GameType:        "Survival",
					Port4:           "19132",
				},
			}.Build()
			lc.WriteTo(pong.Bytes(), src)
		}
	}
}

// Address returns the remote endpoint for the proxy to dial.
func (fs *fakeServer) Address() *net.UDPAddr { return fs.addr }

// Traffic is the number of datagrams received from the proxy.
func (fs *fakeServer) Traffic() int {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	return fs.total
}

// SetReply toggles whether the fake replies to pings (used to simulate
// a transient server silence).
func (fs *fakeServer) SetReply(on bool) {
	fs.mu.Lock()
	fs.reply = on
	fs.mu.Unlock()
}

// DistinctSenders counts the distinct proxy-side source addresses, i.e.
// one per distinct proxy-to-server connection (datagrams from the proxy
// data listener share a fixed source port; each client connection
// originates from a new DialUDP ephemeral port).
func (fs *fakeServer) DistinctSenders() int {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	return len(fs.got)
}

// Stop kills the fake server (making it a dead port for the proxy).
func (fs *fakeServer) stop() {
	if fs.lc != nil {
		fs.lc.Close()
		fs.lc = nil
	}
}

// Revive re-binds the fake server on the same port (server recovery).
func (fs *fakeServer) revive() {
	if fs.lc != nil {
		return
	}
	fs.reply = true
	_ = fs.listen()
}

// testClient is a minimal Minecraft-console stand-in: real UDP socket,
// crafted pings, a pump goroutine that buffers replies for takePong.
type testClient struct {
	conn    *net.UDPConn
	packets chan []byte
}

func startTestClient(t *testing.T) *testClient {
	t.Helper()
	c, err := net.ListenUDP("udp", nil)
	require.NoError(t, err)
	tc := &testClient{conn: c, packets: make(chan []byte, 16)}
	go tc.pump()
	t.Cleanup(tc.shut)
	return tc
}

func (tc *testClient) pump() {
	buf := make([]byte, 4096)
	for {
		n, err := tc.conn.Read(buf)
		if err != nil {
			return
		}
		tc.packets <- append([]byte(nil), buf[:n]...)
	}
}

func (tc *testClient) sendPing(dst *net.UDPAddr, seq byte) {
	// Hand-crafted: proto.Build() intentionally emits a *pong* (it exists
	// to forge the offline pong), so a real console ping (ID 0x01) is
	// assembled here explicitly.
	pt := make([]byte, 8)
	pt[0] = seq
	id := make([]byte, 8)
	id[7] = seq

	var buf bytes.Buffer
	buf.WriteByte(proto.UnconnectedPingID)
	buf.Write(pt)
	buf.Write(id)
	buf.Write(fakeMagic)
	buf.Write([]byte{0, 0}) // zero payload length
	_, _ = tc.conn.WriteTo(buf.Bytes(), dst)
}

// takePong waits up to timeout for a decoded pong reply.
func (tc *testClient) takePong(timeout time.Duration) (pkg *proto.UnconnectedPing, ok bool) {
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case b := <-tc.packets:
		p, err := proto.ReadUnconnectedPing(b)
		if err != nil {
			return nil, false
		}
		return p, true
	case <-timer.C:
		return nil, false
	}
}

func (tc *testClient) shut() { tc.conn.Close() }

// bringUp starts a proxy aimed at the fake server and waits (polling with
// pings) until it demonstrates life by forwarding traffic.
func bringUp(t *testing.T, fs *fakeServer, prefs ProxyPrefs) (*ProxyServer, *testClient) {
	t.Helper()
	prefs.RemoteServer = fs.Address().String()
	if prefs.BindAddress == "" {
		prefs.BindAddress = "127.0.0.1"
	}
	// A picked ping port avoids clobbering a real 19132 (0 = conventional).
	if prefs.PingPort == 0 {
		prefs.PingPort = uint16(pickFreePort(t))
	}
	pr, err := New(prefs)
	require.NoError(t, err)
	go pr.Start()
	t.Cleanup(func() { pr.Close() })

	tc := startTestClient(t)
	dst := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: int(pr.boundPort)}
	deadline := time.Now().Add(5 * time.Second)
	seq := byte(0)
	for time.Now().Before(deadline) {
		tc.sendPing(dst, seq)
		seq++
		time.Sleep(50 * time.Millisecond)
		if fs.Traffic() > 0 {
			return pr, tc
		}
	}
	t.Fatalf("proxy never forwarded traffic to the fake server")
	return nil, nil
}

func pickFreePort(t *testing.T) int {
	t.Helper()
	l, err := net.ListenUDP("udp", nil)
	require.NoError(t, err)
	port := l.LocalAddr().(*net.UDPAddr).Port
	l.Close()
	return port
}

// waitFor polls cond up to timeout, failing the test with desc if it never
// becomes true.
func waitFor(t *testing.T, desc string, timeout time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.After(timeout)
	tick := time.NewTicker(10 * time.Millisecond)
	defer tick.Stop()
	for {
		if cond() {
			return
		}
		select {
		case <-deadline:
			t.Fatalf("%s: not satisfied within %s", desc, timeout)
		case <-tick.C:
		}
	}
}

// -------------------------------------------------------------------------
// Cycle 1: happy path — console ping reaches the fake server, and the
// rewritten pong (server ID + bound port) comes back to the console.
// -------------------------------------------------------------------------

func TestHappyPath(t *testing.T) {
	fs := startFakeServer(t, pickFreePort(t))

	pr, tc := bringUp(t, fs, ProxyPrefs{
		IdleTimeout: 20 * time.Second,
		PingPort:    0, // ephemeral (avoids clobbering a real 19132)
	})
	dst := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: int(pr.boundPort)}

	tc.sendPing(dst, 1)
	pkg, ok := tc.takePong(3 * time.Second)
	require.True(t, ok, "expected a pong from the fake server via the proxy")

	assert.Equal(t, "fake motd", pkg.Pong.MOTD)
	// The proxy rewrites the server ID to its own instance ID.
	assert.Equal(t, fmt.Sprintf("%d", serverID), pkg.Pong.ServerID)
	// ...and the port to the proxy's bound port.
	assert.Equal(t, fmt.Sprintf("%d", pr.boundPort), pkg.Pong.Port4)
	assert.Equal(t, fmt.Sprintf("%d", pr.boundPort), pkg.Pong.Port6)
}

// tryTakePong is the non-blocking variant of takePong (for waitFor polling).
func (tc *testClient) tryTakePong() *proto.UnconnectedPing {
	select {
	case b := <-tc.packets:
		pkg, err := proto.ReadUnconnectedPing(b)
		if err != nil {
			return nil
		}
		return pkg
	default:
		return nil
	}
}

// ---------------------------------------------------------------------------
// Cycle 2 — Group-7 regression: a transient read-delay expiration must NOT
// tear the connection down or mark the server offline.
// ---------------------------------------------------------------------------

func TestTransientReadTimeoutKeepsConnectionAlive(t *testing.T) {
	// Compress the production 5s watchdog (the test's raison d'être for
	// the promotion of serverReadDelay). Restore under the lock via the setter.
	setServerReadDelay(250 * time.Millisecond)
	t.Cleanup(func() { setServerReadDelay(5 * time.Second) })

	// Generous idle so it doesn't collide with the watchdog test.
	fs := startFakeServer(t, pickFreePort(t))

	pr, tc := bringUp(t, fs, ProxyPrefs{
		IdleTimeout: 20 * time.Second,
	})

	entries := func() int {
		return pr.clientMap.Len()
	}

	// Repro the production false positive: silence the server, then
	// forward a ping — the worker sets the shared conn's deadline
	// (+250ms), the fake never answers, and the reader's pending
	// ReadFrom expires with "i/o timeout".
	fs.SetReply(false)
	tc.sendPing(dstFor(pr), 2)
	time.Sleep(400 * time.Millisecond) // let the deadline elapse

	// Old code: "i/o timeout" matches the regex -> connection torn down
	// and server marked OFFLINE. Fixed code: transient -> connection kept.
	require.False(t, pr.serverOffline.IsSet(), "server must not be marked offline after a transient silence")
	assert.Equal(t, 1, entries(), "connection mapping must survive a transient silence")

	// The connection is still usable: the fake resumes, a new ping
	// gets a pong through the surviving connection.
	fs.SetReply(true)
	tc.sendPing(dstFor(pr), 3)
	pkg, ok := tc.takePong(3 * time.Second)
	require.True(t, ok, "expected pong via surviving connection")
	assert.Equal(t, "fake motd", pkg.Pong.MOTD)
}

func dstFor(pr *ProxyServer) *net.UDPAddr {
	return &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: int(pr.boundPort)}
}

// ---------------------------------------------------------------------------
// Cycle 3 — RemovePorts strips the port fields from the pong.
// ---------------------------------------------------------------------------

func TestRemovePortsStripsPortFields(t *testing.T) {
	fs := startFakeServer(t, pickFreePort(t))

	pr, tc := bringUp(t, fs, ProxyPrefs{
		IdleTimeout: 20 * time.Second,
		RemovePorts: true,
	})

	tc.sendPing(dstFor(pr), 1)
	pkg, ok := tc.takePong(3 * time.Second)
	require.True(t, ok, "expected pong via RemovePorts proxy")

	// The fake advertises Port4 19132; RemovePorts must blank both ports.
	assert.Equal(t, "", pkg.Pong.Port4, "port4 must be stripped")
	assert.Equal(t, "", pkg.Pong.Port6, "port6 must be stripped")
	// The rest of the pong is intact.
	assert.Equal(t, "fake motd", pkg.Pong.MOTD)
	assert.NotEmpty(t, pkg.Pong.ServerID)
}

// ---------------------------------------------------------------------------
// Cycle 4 — idle eviction: a client that goes silent for IdleTimeout is
// reaped, and the proxy transparently reconnects on the next packet.
// ---------------------------------------------------------------------------

func TestIdleEvictionReapsSilentClient(t *testing.T) {
	// Fast ticks (normally 5s) so the eviction window is observable.
	origTick := idleCheckInterval
	idleCheckInterval = 100 * time.Millisecond
	t.Cleanup(func() { idleCheckInterval = origTick })

	const idle = 400 * time.Millisecond
	fs := startFakeServer(t, pickFreePort(t))

	pr, tc := bringUp(t, fs, ProxyPrefs{IdleTimeout: idle})

	entries := func() int {
		return pr.clientMap.Len()
	}

	// Handshake: establish the single connection.
	tc.sendPing(dstFor(pr), 1)
	waitFor(t, "handshake pong", 3*time.Second, func() bool { return tc.tryTakePong() != nil })
	assert.Equal(t, 1, entries(), "one connection after handshake")

	// Client goes silent; eviction removes the entry (next tick after
	// lastActive + idle).
	waitFor(t, "idle eviction", 3*time.Second, func() bool { return entries() == 0 })

	// A fresh ping opens a new connection transparently.
	tc.sendPing(dstFor(pr), 9)
	waitFor(t, "post-eviction reconnect", 3*time.Second, func() bool { return entries() == 1 })
}

// ---------------------------------------------------------------------------
// Cycle 5 — multi-worker: NumWorkers > 1 still proxies (pins Group 4's
// clamp; zero workers would previously yield a zombie that never forwards).
// ---------------------------------------------------------------------------

func TestMultiWorkerStillProxies(t *testing.T) {
	fs := startFakeServer(t, pickFreePort(t))

	pr, tc := bringUp(t, fs, ProxyPrefs{
		IdleTimeout: 20 * time.Second,
		NumWorkers:  2,
	})

	tc.sendPing(dstFor(pr), 1)
	pkg, ok := tc.takePong(3 * time.Second)
	require.True(t, ok, "expected pong via a 2-worker proxy")
	assert.Equal(t, "fake motd", pkg.Pong.MOTD)
}

// ---------------------------------------------------------------------------
// Cycle 6 — startup bind failure: Start() errors and the already-bound ping
// listener is released (Group 4 leak fix). Verified by being able to
// re-bind that exact ping port on a second proxy.
// ---------------------------------------------------------------------------

func TestStartupBindFailureReleasesResources(t *testing.T) {
	gamePort := uint16(pickFreePort(t))
	pingPort := uint16(pickFreePort(t))

	// Hold the GAME port so Start() progresses past the ping bind and then
	// fails on the game listener — exercising the Group-4 leak path.
	holder, err := net.ListenUDP("udp", &net.UDPAddr{Port: int(gamePort)})
	require.NoError(t, err)
	defer holder.Close()

	fs := startFakeServer(t, pickFreePort(t))

	pr, err := New(ProxyPrefs{
		BindAddress:  "127.0.0.1",
		BindPort:     gamePort,
		RemoteServer: fs.Address().String(),
		IdleTimeout:  20 * time.Second,
		PingPort:     pingPort,
	})
	require.NoError(t, err)

	err = pr.Start()
	require.Error(t, err, "Start must fail when the game port is held")
	pr.Close() // Close on a failed Start must be safe (nil guards)

	// The ping listener was bound BEFORE the failure — if it leaked,
	// rebinding it here would fail. Free it (holder) and rebind both.
	holder.Close()
	leakCheck, err := net.ListenUDP("udp", &net.UDPAddr{Port: int(pingPort)})
	require.NoError(t, err, "ping port must be free after failed Start (no leak)")
	leakCheck.Close()
}
