package clientmap

import (
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Remote lives in TEST-NET-1 (RFC 5737): unroutable, but harmless for
// UDP since there is no handshake.
func testRemote() *net.UDPAddr {
	return &net.UDPAddr{IP: net.ParseIP("192.0.2.1"), Port: 4321}
}

func testClient(ip string) *net.UDPAddr {
	return &net.UDPAddr{IP: net.ParseIP(ip), Port: 1}
}

// blockingReader blocks on a real read until the connection is closed,
// then signals onClosed. (NOTE: Read(nil) does NOT block on UDP sockets
// — it returns (0, nil) instantly, so a nil buffer would defeat this test.)
func blockingReader(conn *net.UDPConn, onClosed chan<- struct{}) {
	buf := make([]byte, 1)
	_, err := conn.Read(buf)
	if err != nil {
		onClosed <- struct{}{}
	}
}

func TestNewAndIdempotentClose(t *testing.T) {
	cm := New(time.Hour, time.Millisecond)
	require.NotNil(t, cm)

	assert.NotPanics(t, cm.Close)
	assert.NotPanics(t, cm.Close) // guarded by dead flag
}

func TestDeleteSilentForUnknown(t *testing.T) {
	cm := New(time.Hour, time.Hour)
	defer cm.Close()

	assert.NotPanics(t, func() {
		cm.Delete(testClient("10.1.1.1"))
	})
}

func TestGetCreatesThenReuses(t *testing.T) {
	cm := New(time.Hour, time.Hour)
	defer cm.Close()

	var invocations int32
	handler := func(_ *net.UDPConn) {
		atomic.AddInt32(&invocations, 1)
	}

	remote := testRemote()

	conn1, err := cm.Get(testClient("10.0.0.1"), remote, handler)
	require.NoError(t, err)
	require.NotNil(t, conn1)

	assert.Eventually(t, func() bool {
		return atomic.LoadInt32(&invocations) == 1
	}, time.Second, time.Millisecond, "first handler should fire")

	// Same client address must be reused (no new connection, no 2nd handler).
	conn2, err := cm.Get(testClient("10.0.0.1"), remote, handler)
	require.NoError(t, err)
	assert.Same(t, conn1, conn2)

	// Distinct client address forces a brand-new connection.
	conn3, err := cm.Get(testClient("10.0.0.2"), remote, handler)
	require.NoError(t, err)
	assert.NotSame(t, conn1, conn3)
	assert.Eventually(t, func() bool {
		return atomic.LoadInt32(&invocations) == 2
	}, time.Second, time.Millisecond, "second client should launch handler")
}

// Deleting an existing client closes the connection and drops it, so a
// subsequent Get must spin up a fresh connection (handler fires again).
func TestDeleteClosesAndRecycles(t *testing.T) {
	cm := New(time.Hour, time.Hour)
	defer cm.Close()

	var invocations int32
	handler := func(_ *net.UDPConn) {
		atomic.AddInt32(&invocations, 1)
	}

	remote := testRemote()
	client := testClient("10.0.0.1")

	conn1, err := cm.Get(client, remote, handler)
	require.NoError(t, err)
	assert.Eventually(t, func() bool {
		return atomic.LoadInt32(&invocations) == 1
	}, time.Second, time.Millisecond, "first handler should fire")

	cm.Delete(client)

	conn2, err := cm.Get(client, remote, handler)
	require.NoError(t, err)
	assert.NotSame(t, conn1, conn2, "deleted client should not be reused")
	assert.Eventually(t, func() bool {
		return atomic.LoadInt32(&invocations) == 2
	}, time.Second, time.Millisecond, "recycled connection should relaunch handler")
}

// An 8-byte (short) IP makes DialUDP fail with a non-IPv6 address
// (probe-verified); the error must propagate and no entry may hang.
func TestGetPropagatesDialFailure(t *testing.T) {
	cm := New(time.Hour, time.Hour)
	defer cm.Close()

	failingRemote := &net.UDPAddr{IP: make(net.IP, 8)}

	conn, err := cm.Get(testClient("10.0.0.1"), failingRemote, func(_ *net.UDPConn) {})
	require.Error(t, err)
	assert.Nil(t, conn)

	// Entry must not linger: a follow-up Get with a good remote still works
	// (i.e., it was not blocked by a poisoned half-state).
	good, err := cm.Get(testClient("10.0.0.1"), testRemote(), func(_ *net.UDPConn) {})
	require.NoError(t, err)
	assert.NotNil(t, good)
}

// Idle timeout (20 ms) + tick interval (5 ms): an unused client must be
// evicted and recyclable, proving the cleanup loop closes + removes entries.
func TestIdleEvictionRecycles(t *testing.T) {
	cm := New(20*time.Millisecond, 5*time.Millisecond)
	defer cm.Close()

	var invocations int32
	handler := func(_ *net.UDPConn) {
		atomic.AddInt32(&invocations, 1)
	}

	remote := testRemote()
	client := testClient("10.0.0.1")

	_, err := cm.Get(client, remote, handler)
	require.NoError(t, err)
	assert.Eventually(t, func() bool {
		return atomic.LoadInt32(&invocations) == 1
	}, time.Second, time.Millisecond, "first handler should fire")

	// Let the entry age out (idle timeout 20ms, ticks every 5ms).
	// NOTE: Get() refreshes lastActive, so we must NOT call it while waiting.
	time.Sleep(100 * time.Millisecond)

	_, err = cm.Get(client, remote, handler)
	require.NoError(t, err)

	assert.Eventually(t, func() bool {
		return atomic.LoadInt32(&invocations) == 2
	}, time.Second, time.Millisecond,
		"idle entry should be evicted and the recycled connection relaunched")
}

// Closing must shut down every outstanding client connection (observable
// through the blocked reader waking up) and tolerate repeated calls.
func TestCloseShutsDownClients(t *testing.T) {
	cm := New(time.Hour, time.Hour)

	shutdown := make(chan struct{}, 2)

	handler := func(conn *net.UDPConn) {
		blockingReader(conn, shutdown)
	}

	remote := testRemote()
	_, err := cm.Get(testClient("10.0.0.1"), remote, handler)
	require.NoError(t, err)
	_, err = cm.Get(testClient("10.0.0.2"), remote, handler)
	require.NoError(t, err)

	// Give handlers a moment to reach their blocking Read.
	time.Sleep(10 * time.Millisecond)

	cm.Close()

	timeout := time.AfterFunc(2*time.Second, func() {
		// Unblock readers that are stuck (defensive; Close is synchronous).
	})
	defer timeout.Stop()

	// Allow both reader goroutines to observe the closure.
	for i := 0; i < 2; i++ {
		select {
		case <-shutdown:
		case <-time.After(2 * time.Second):
			t.Fatalf("close %d of 2 did not wake its blocked reader within 2s", i+1)
		}
	}

	assert.NotPanics(t, cm.Close)
}

// Hammer Get + Delete from many goroutines to shake out lock discipline;
// intended to run under -race.
func TestConcurrentAccessRace(t *testing.T) {
	cm := New(time.Hour, time.Millisecond)
	defer cm.Close()

	remote := testRemote()

	var wg sync.WaitGroup
	start := make(chan struct{})

	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			client := testClient(intToString(i))
			cm.Get(client, remote, func(_ *net.UDPConn) {})
			cm.Delete(client)
		}(i)
	}

	close(start)
	wg.Wait()
}

// intToString renders "10.0.0.<i>" for i < 256.
func intToString(i int) string {
	return fmt.Sprintf("10.0.0.%d", i)
}
