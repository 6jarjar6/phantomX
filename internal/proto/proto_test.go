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

// Strict truncation behavior: the decoder rejects short headers (<35 bytes)
// and declared payload lengths longer than the bytes present.
// Per cutoff for a 39-byte packet (prefix fixed at 0,4, payload at [35:39]):
//
//	0-34  -> error (short header)
//	35-38 -> error (declared length exceeds available bytes)
//	39    -> passes (full payload)
func TestReadUnconnectedPingTruncated(t *testing.T) {
	full := make([]byte, 39)
	full[0] = 0x01
	copy(full[33:], []byte{0, 4})
	copy(full[35:], "MOTP")

	wantErr := func(cutoff int) bool {
		return cutoff < 39
	}

	for cutoff := 0; cutoff <= len(full); cutoff++ {
		_, err := ReadUnconnectedPing(full[:cutoff])
		if wantErr(cutoff) {
			assert.Error(t, err, "cutoff %d should error", cutoff)
		} else {
			assert.NoError(t, err, "cutoff %d should be tolerated", cutoff)
		}
	}

	// Sentinel discrimination: short header vs truncated payload.
	_, err := ReadUnconnectedPing(full[:34])
	assert.ErrorIs(t, err, ErrShortHeader)
	_, err = ReadUnconnectedPing(full[:36])
	assert.ErrorIs(t, err, ErrTruncatedPong)

	// A complete header with a zero-length declaration is valid on its own.
	zeroLen := make([]byte, MinHeaderSize)
	zeroLen[0] = 0x01 // prefix bytes [33:35] are already 0
	_, err = ReadUnconnectedPing(zeroLen)
	assert.NoError(t, err)
}

// Strictness: a declared length longer than the payload actually present is
// rejected, not silently accepted.
func TestReadUnconnectedPingDeclaredLengthTooLong(t *testing.T) {
	pingTime := [8]byte{1, 2, 3, 4, 5, 6, 7, 8}
	clientID := [8]byte{9, 10, 11, 12, 13, 14, 15, 16}
	magic := [16]byte{0, 0xFF, 0xFF, 0, 0xFE, 0xFE, 0xFE, 0xFE,
		0xFD, 0xFD, 0xFD, 0xFD, 0x12, 0x34, 0x56, 0x78}

	packet := buildPing(0x01, pingTime, clientID, magic, "AB")
	// buildPing places the length prefix at [33:35]; claim 10 bytes of
	// payload but only supply 2.
	packet[33] = byte(0)
	packet[34] = byte(10)

	_, err := ReadUnconnectedPing(packet)
	assert.ErrorIs(t, err, ErrTruncatedPong)
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

// Empty payload edge: an all-empty struct still yields a 1-byte payload
// (the enforced trailing ';' via ""), and a zero-length declaration is legal.
func TestZeroLengthPongPayload(t *testing.T) {
	zeroTime := [8]byte{}
	zeroID := [8]byte{}
	magic := [16]byte{0, 0xFF, 0xFF, 0, 0xFE, 0xFE, 0xFE, 0xFE,
		0xFD, 0xFD, 0xFD, 0xFD, 0x12, 0x34, 0x56, 0x78}

	// A 1-byte payload (";") with matching length prefix must parse.
	minimal := buildPing(0x01, zeroTime, zeroID, magic, ";")
	reply, err := ReadUnconnectedPing(minimal)
	assert.NoError(t, err)
	assert.Empty(t, reply.Pong.MOTD)

	// A zero-length declaration with zero payload bytes is also valid
	// (buildPing already emits a 0/0 prefix for empty payload).
	empty := buildPing(0x01, zeroTime, zeroID, magic, "")
	reply2, err := ReadUnconnectedPing(empty)
	assert.NoError(t, err)
	assert.Empty(t, reply2.Pong.MOTD)
}
