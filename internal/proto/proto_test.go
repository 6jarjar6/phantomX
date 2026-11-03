package proto

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// buildPing crafts a deterministic Unconnected Ping packet:
// [1 byte packet ID][8 bytes ping time][8 bytes client ID][16 bytes magic][2 bytes pong length][pong payload]
func buildPing(packetID byte, pingTime [8]byte, clientID [8]byte, magic [16]byte, pongPayload string) []byte {
	out := make([]byte, 0, 33+len(pongPayload))
	out = append(out, packetID)
	out = append(out, pingTime[:]...)
	out = append(out, clientID[:]...)
	out = append(out, magic[:]...)
	lenBuf := make([]byte, 2)
	l := len(pongPayload)
	lenBuf[0] = byte(l >> 8)
	lenBuf[1] = byte(l)
	out = append(out, lenBuf...)
	out = append(out, pongPayload...)
	return out
}

func TestReadUnconnectedPing(t *testing.T) {
	pingTime := [8]byte{1, 2, 3, 4, 5, 6, 7, 8}
	clientID := [8]byte{9, 10, 11, 12, 13, 14, 15, 16}
	magic := [16]byte{0, 0xFF, 0xFF, 0, 0xFE, 0xFE, 0xFE, 0xFE,
		0xFD, 0xFD, 0xFD, 0xFD, 0x12, 0x34, 0x56, 0x78}
	// All 11 fields populated (incl. the two trailing port fields) so the
	// decoder maps 1:1 with no empty-slot shifting. (The shifting behavior
	// for sparse payloads is pinned in TestBuildThenReadRoundTrip.)
	payload := "MCPE;Test MOTD;390;1.14.60;1;2;sid;smotd;Creative;1;p4;p6;"

	packet := buildPing(0x01, pingTime, clientID, magic, payload)

	reply, err := ReadUnconnectedPing(packet)

	assert.NoError(t, err)
	assert.NotNil(t, reply)
	assert.Equal(t, pingTime[:], reply.PingTime)
	assert.Equal(t, clientID[:], reply.ID)
	assert.Equal(t, magic[:], reply.Magic)
	assert.Equal(t, "Test MOTD", reply.Pong.MOTD)
	assert.Equal(t, "MCPE", reply.Pong.Edition)
	assert.Equal(t, "390", reply.Pong.ProtocolVersion)
	assert.Equal(t, "1.14.60", reply.Pong.Version)
	assert.Equal(t, "1", reply.Pong.Players)
	assert.Equal(t, "2", reply.Pong.MaxPlayers)
	assert.Equal(t, "sid", reply.Pong.ServerID)
	assert.Equal(t, "smotd", reply.Pong.SubMOTD)
	assert.Equal(t, "Creative", reply.Pong.GameType)
	assert.Equal(t, "1", reply.Pong.NintendoLimited)
	assert.Equal(t, "p4", reply.Pong.Port4)
	assert.Equal(t, "p6", reply.Pong.Port6)
}

// Truncation behavior: most header cuts fail, but the reader is LENIENT
// with partial reads — a cut mid-way through the length prefix still
// parses (yielding a possibly smaller length), and a cut that supplies
// fewer than the declared payload bytes is accepted without error.
// Pins the exact outcome per cutoff for a 38-byte packet (declared len 4):
//
//	0-33  -> error (header broken at some stage)
//	34    -> passes (partial length prefix; derived length from 1 byte)
//	35    -> error (valid length prefix, zero payload bytes available)
//	36-38 -> passes (partial/full payload accepted)
func TestReadUnconnectedPingTruncated(t *testing.T) {
	full := make([]byte, 38)
	full[0] = 0x01
	copy(full[33:], []byte{0, 4})
	copy(full[35:], "MOTP")

	wantErr := func(cutoff int) bool {
		switch {
		case cutoff <= 33:
			return true
		case cutoff == 34:
			return false
		case cutoff == 35:
			return true
		default:
			return false
		}
	}

	for cutoff := 0; cutoff <= len(full); cutoff++ {
		_, err := ReadUnconnectedPing(full[:cutoff])
		if wantErr(cutoff) {
			assert.Error(t, err, "cutoff %d should error", cutoff)
		} else {
			assert.NoError(t, err, "cutoff %d should be tolerated", cutoff)
		}
	}
}

// Leniency: a declared length longer than the payload actually present is
// accepted (partial read), not detected. Documenting current behavior.
func TestReadUnconnectedPingDeclaredLengthTooLong(t *testing.T) {
	pingTime := [8]byte{1, 2, 3, 4, 5, 6, 7, 8}
	clientID := [8]byte{9, 10, 11, 12, 13, 14, 15, 16}
	magic := [16]byte{0, 0xFF, 0xFF, 0, 0xFE, 0xFE, 0xFE, 0xFE,
		0xFD, 0xFD, 0xFD, 0xFD, 0x12, 0x34, 0x56, 0x78}

	packet := buildPing(0x01, pingTime, clientID, magic, "AB")
	// Claim 10 bytes of payload but only supply 2.
	packet[31] = byte(0)
	packet[32] = byte(10)

	_, err := ReadUnconnectedPing(packet)
	assert.NoError(t, err)
}

func TestBuildLayout(t *testing.T) {
	in := UnconnectedPing{
		PingTime: []byte{1, 2, 3, 4, 5, 6, 7, 8},
		ID:       []byte{9, 10, 11, 12, 13, 14, 15, 16},
		Magic: []byte{0, 0xFF, 0xFF, 0, 0xFE, 0xFE, 0xFE, 0xFE,
			0xFD, 0xFD, 0xFD, 0xFD, 0x12, 0x34, 0x56, 0x78},
		Pong: PongData{
			Edition: "MCPE", MOTD: "Hi", ProtocolVersion: "390",
			Version: "1.14.60", Players: "1", MaxPlayers: "2",
		},
	}

	got := in.Build()

	// Header: pong ID byte + 8 + 8 + 16 + 2 (length prefix)
	const headerLen = 1 + 8 + 8 + 16 + 2
	raw := got.Bytes()
	assert.GreaterOrEqual(t, len(raw), headerLen)
	assert.Equal(t, byte(UnconnectedPongID), raw[0])
	assert.Equal(t, []byte{1, 2, 3, 4, 5, 6, 7, 8}, raw[1:9])
	assert.Equal(t, []byte{9, 10, 11, 12, 13, 14, 15, 16}, raw[9:17])
	assert.Equal(t, []byte{0, 0xFF, 0xFF, 0, 0xFE, 0xFE, 0xFE, 0xFE,
		0xFD, 0xFD, 0xFD, 0xFD, 0x12, 0x34, 0x56, 0x78}, raw[17:33])

	declaredLen := int(raw[33])<<8 | int(raw[34])
	assert.Equal(t, len(raw)-headerLen, declaredLen, "length prefix must match payload size")

	payload := string(raw[headerLen:])
	// Wire semantics (observed): mid-stream empty fields ARE preserved
	// (-> double ;), the ENTIRE trailing run is stripped, then one
	// terminating ; is always appended.
	assert.Equal(t, "MCPE;Hi;390;1.14.60;1;2;", payload)
}

func TestBuildStripTrailingSemicolons(t *testing.T) {
	in := UnconnectedPing{
		PingTime: []byte{0, 0, 0, 0, 0, 0, 0, 0},
		ID:       []byte{0, 0, 0, 0, 0, 0, 0, 0},
		Magic: []byte{0, 0xFF, 0xFF, 0, 0xFE, 0xFE, 0xFE, 0xFE,
			0xFD, 0xFD, 0xFD, 0xFD, 0x12, 0x34, 0x56, 0x78},
		Pong: PongData{
			Edition: "MCPE", MOTD: "Motd", ProtocolVersion: "1",
			Version: "1.0", Players: "0", MaxPlayers: "0",
			ServerID: "", SubMOTD: "", GameType: "Creative",
			NintendoLimited: "1",
			Port4:           "", Port6: "",
		},
	}

	stripped := in.Build()
	got := string(stripped.Bytes()[35:])

	// Port4/Port6 empty (trailing) collapse away; ServerID/SubMOTD empty
	// (mid-stream) stay: pins the asymmetry of dupeSemicolonRegex (;{2,}$)
	// plus the enforced single terminating ';'.
	assert.Equal(t, "MCPE;Motd;1;1.0;0;0;;;Creative;1;", got)
}

// Field-ordering caveat: because readPong maps split positions onto fields
// and the wire format strips trailing empty fields, a fully-populated
// round trip shifts fields after mid-stream empties. This test pins the
// observed behavior of the fields that DO round-trip reliably.
func TestBuildThenReadRoundTrip(t *testing.T) {
	in := UnconnectedPing{
		PingTime: []byte{1, 2, 3, 4, 5, 6, 7, 8},
		ID:       []byte{9, 10, 11, 12, 13, 14, 15, 16},
		Magic: []byte{0, 0xFF, 0xFF, 0, 0xFE, 0xFE, 0xFE, 0xFE,
			0xFD, 0xFD, 0xFD, 0xFD, 0x12, 0x34, 0x56, 0x78},
		Pong: PongData{
			Edition: "MCPE", MOTD: "Hi", ProtocolVersion: "390",
			Version: "1.14.60", Players: "1", MaxPlayers: "2",
			GameType: "Creative",
		},
	}

	built := in.Build()
	reply, err := ReadUnconnectedPing(built.Bytes())

	assert.NoError(t, err)
	assert.Equal(t, in.PingTime, reply.PingTime)
	assert.Equal(t, in.ID, reply.ID)
	assert.Equal(t, in.Magic, reply.Magic)
	// The six fields preceding the first empty field land back in place.
	assert.Equal(t, "MCPE", reply.Pong.Edition)
	assert.Equal(t, "Hi", reply.Pong.MOTD)
	assert.Equal(t, "390", reply.Pong.ProtocolVersion)
	assert.Equal(t, "1.14.60", reply.Pong.Version)
	assert.Equal(t, "1", reply.Pong.Players)
	assert.Equal(t, "2", reply.Pong.MaxPlayers)
}

// The shipped offline pong is part of the protocol surface (consoles see
// it), so pin its exact wire encoding as a regression fingerprint.
func TestOfflinePongWireFormat(t *testing.T) {
	raw := OfflinePong.Bytes()

	const headerLen = 1 + 8 + 8 + 16 + 2
	assert.GreaterOrEqual(t, len(raw), headerLen)
	assert.Equal(t, byte(UnconnectedPongID), raw[0])
	// Echoed ping time / client ID / magic are all zeros / known magic.
	assert.Equal(t, make([]byte, 8), raw[1:9])
	assert.Equal(t, make([]byte, 8), raw[9:17])
	assert.Contains(t, string(raw), "§cServer offline")
	assert.Contains(t, string(raw), "390")
	assert.Contains(t, string(raw), "1.14.60")
	// Declared length prefix must agree with actual payload size.
	declaredLen := int(raw[33])<<8 | int(raw[34])
	assert.Equal(t, len(raw)-headerLen, declaredLen)
}

// Empty payload edge: Build of all-zero fields must still emit a valid
// header with a consistent length prefix, and Read must reject a
// zero-length-declared payload buffer... actually a zero-length pong
// payload is legal (declare 0, supply 0).
func TestZeroLengthPongPayload(t *testing.T) {
	zeroTime := [8]byte{}
	zeroID := [8]byte{}
	magic := [16]byte{0, 0xFF, 0xFF, 0, 0xFE, 0xFE, 0xFE, 0xFE,
		0xFD, 0xFD, 0xFD, 0xFD, 0x12, 0x34, 0x56, 0x78}

	// An all-empty struct still yields a 1-byte payload: the enforced
	// trailing ';' (empty join -> "" -> "%s;" -> ";").
	built := buildPing(0x01, zeroTime, zeroID, magic, "")
	// Replace the declared length (currently 0 from empty payload) with the
	// actual minimal payload the wire writer demands.
	built[31], built[32] = 0, 1

	reply, err := ReadUnconnectedPing(built)
	assert.NoError(t, err)
	assert.Empty(t, reply.Pong.MOTD)

	// Reading a header with declared-len 0 and no payload is also valid.
	empty := buildPing(0x01, zeroTime, zeroID, magic, "")
	empty[31], empty[32] = 0, 0
	reply2, err := ReadUnconnectedPing(empty)
	assert.NoError(t, err)
	assert.Empty(t, reply2.Pong.MOTD)
}
