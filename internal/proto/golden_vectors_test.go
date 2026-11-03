package proto

import (
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/assert"
)

// The canonical RakNet magic (16 bytes). Stable across all published specs
// (MFDGaming, wikitable, Prismarine) — it is the anti-spoof token.
var raknetMagic = [16]byte{
	0x00, 0xFF, 0xFF, 0x00, 0xFE, 0xFE, 0xFE, 0xFE,
	0xFD, 0xFD, 0xFD, 0xFD, 0x12, 0x34, 0x56, 0x78,
}

// specPong constructs a byte-accurate Unconnected Pong in the SPEC's own
// field order, independent of phantom's struct layout:
//
//	id(1) | clientTs(u64,MSB) | serverGuid(u64,MSB) | magic(16) | data(u16 MSB + chars)
//
// Keeping the encoder separate from the decoder is what makes these vectors
// non-circular: we assert a spec-shaped byte stream decodes into the
// spec's fields, not "phantom round-trips phantom".
func specPong(ts, guid [8]byte, magic [16]byte, data string) []byte {
	out := []byte{UnconnectedPongID}
	out = append(out, ts[:]...)
	out = append(out, guid[:]...)
	out = append(out, magic[:]...)
	l := len(data)
	out = append(out, byte(l>>8), byte(l))
	out = append(out, data...)
	return out
}

// The data field is 12 ;-delimited columns in the spec's canonical order:
//
//	Edition;MOTD1;ProtocolVersion;VersionName;Players;MaxPlayers;
//	ServerUniqueID;MOTD2;GameMode;GameModeNumeric;PortIPv4;PortIPv6
//
// taken from the MFDGaming / wikitable example (fully populated).
const specPongData = "MCPE;Dedicated Server;440;1.17.0;0;10;13253860892328930865;Bedrock level;Survival;1;19132;19133;"

// TestGoldenVectorSpecShape decodes a spec-canonical packet and asserts all
// twelve data columns map onto the right struct fields 1:1 (no drifting).
func TestGoldenVectorSpecShape(t *testing.T) {
	ts := [8]byte{0x00, 0x00, 0x00, 0x00, 0x07, 0x5B, 0xCD, 0x15} // 123456789
	guid := [8]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}

	packet := specPong(ts, guid, raknetMagic, specPongData)

	reply, err := ReadUnconnectedPing(packet)
	assert.NoError(t, err)
	assert.NotNil(t, reply)

	// Header
	assert.Equal(t, ts[:], reply.PingTime, "client timestamp")
	assert.Equal(t, guid[:], reply.ID, "server GUID")
	assert.Equal(t, raknetMagic[:], reply.Magic, "RakNet magic")

	// Twelve data columns, in spec order
	assert.Equal(t, "MCPE", reply.Pong.Edition)
	assert.Equal(t, "Dedicated Server", reply.Pong.MOTD)
	assert.Equal(t, "440", reply.Pong.ProtocolVersion)
	assert.Equal(t, "1.17.0", reply.Pong.Version)
	assert.Equal(t, "0", reply.Pong.Players)
	assert.Equal(t, "10", reply.Pong.MaxPlayers)
	assert.Equal(t, "13253860892328930865", reply.Pong.ServerID)
	assert.Equal(t, "Bedrock level", reply.Pong.SubMOTD)
	assert.Equal(t, "Survival", reply.Pong.GameType)
	assert.Equal(t, "1", reply.Pong.NintendoLimited) // game mode (numeric)
	assert.Equal(t, "19132", reply.Pong.Port4)
	assert.Equal(t, "19133", reply.Pong.Port6)
}

// TestGoldenVectorBigEndiantLengthPrefix asserts the u16 length prefix is
// big-endian (MSB) per spec, and the layout is byte-aligned.
func TestGoldenVectorBigEndiantLengthPrefix(t *testing.T) {
	ts := [8]byte{}
	guid := [8]byte{}
	data := specPongData
	packet := specPong(ts, guid, raknetMagic, data)

	// Layout: 1(id)+8(ts)+8(guid)+16(magic)=33, then 2-byte length prefix @33,34.
	hdr := 1 + 8 + 8 + 16
	assert.Equal(t, hdr, 33)
	preceded := binary.BigEndian.Uint16(packet[33:35])
	assert.Equal(t, uint16(len(data)), preceded, "length prefix is u16 MSB")

	// Payload begins right after the prefix and is exactly the data.
	assert.Equal(t, data, string(packet[hdr+2:hdr+2+len(data)]))
}

// TestGoldenVectorMatchesOurBuilder cross-checks: the spec-canonical encoder
// and phantom's Build() must produce identical headers for equivalent inputs,
// tying the spec shape back to the shipped code.
func TestGoldenVectorMatchesOurBuilder(t *testing.T) {
	ts := [8]byte{0x00, 0x00, 0x00, 0x00, 0x07, 0x5B, 0xCD, 0x15}
	guid := [8]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}

	specStream := specPong(ts, guid, raknetMagic, specPongData)

	build := UnconnectedPing{
		PingTime: ts[:],
		ID:       guid[:],
		Magic:    raknetMagic[:],
		Pong: PongData{
			Edition:         "MCPE",
			MOTD:            "Dedicated Server",
			ProtocolVersion: "440",
			Version:         "1.17.0",
			Players:         "0",
			MaxPlayers:      "10",
			ServerID:        "13253860892328930865",
			SubMOTD:         "Bedrock level",
			GameType:        "Survival",
			NintendoLimited: "1",
			Port4:           "19132",
			Port6:           "19133",
		},
	}
	built := build.Build()

	assert.Equal(t, specStream, built.Bytes(), "phantom's emitter reproduces the spec shape")
}

// TestRakNetMagicConstant pins the magic constant so an accidental edit to
// the shared token is caught.
func TestRakNetMagicConstant(t *testing.T) {
	expected := []byte{
		0x00, 0xFF, 0xFF, 0x00, 0xFE, 0xFE, 0xFE, 0xFE,
		0xFD, 0xFD, 0xFD, 0xFD, 0x12, 0x34, 0x56, 0x78,
	}
	assert.Equal(t, expected, raknetMagic[:])
}

// Fuzz seed corpus: a valid spec packet, a couple of truncations, pure junk,
// and empty.
func fuzzSeedCorpus() [][]byte {
	valid := specPong([8]byte{0x00, 0x00, 0x00, 0x00, 0x07, 0x5B, 0xCD, 0x15},
		[8]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}, raknetMagic, specPongData)

	return [][]byte{
		valid,
		valid[:10],                     // header truncated
		valid[:33],                     // stops at the length prefix
		valid[:33+2],                   // prefix, no payload
		{},                             // empty
		{0x00, 0x00, 0x00, 0x00},       // junk
		{0x1c, 0xAA, 0xBB, 0xCC, 0xDD}, // partial
	}
}

// FuzzReadUnconnectedPing is the crash-safety net: the decoder must never
// panic, OOB, or deadlock on arbitrary input, including malformed/truncated
// packets. This is the primary value of fuzzing a lenient parser.
func FuzzReadUnconnectedPing(f *testing.F) {
	for _, seed := range fuzzSeedCorpus() {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		reply, err := ReadUnconnectedPing(data)
		// No panic is the bar; err or success both acceptable.
		// Structural invariant: on success, echoes are sized correctly.
		if err == nil && reply != nil {
			assert.Len(t, reply.PingTime, 8)
			assert.Len(t, reply.ID, 8)
			assert.Len(t, reply.Magic, 16)
		}
	})
}
