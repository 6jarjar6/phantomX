package proto

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/jhead/phantom/internal/util"
)

var UnconnectedPingID byte = 0x01
var UnconnectedPongID byte = 0x1C

// MinHeaderSize is the minimum size of a valid unconnected ping/pong header:
// 1 (id) + 8 (timestamp) + 8 (GUID) + 16 (magic) + 2 (payload length).
const MinHeaderSize = 35

// Sentinel errors for malformed packets, so callers can distinguish validation
// failures from transport faults.
var (
	ErrShortHeader   = errors.New("short header: expected at least 35 bytes")
	ErrTruncatedPong = errors.New("truncated pong: declared length exceeds available bytes")
)

type UnconnectedPing struct {
	PingTime []byte
	ID       []byte
	Magic    []byte
	Pong     PongData
}

type PongData struct {
	Edition         string
	MOTD            string
	ProtocolVersion string
	Version         string
	Players         string
	MaxPlayers      string
	ServerID        string
	SubMOTD         string
	GameType        string
	NintendoLimited string
	Port4           string
	Port6           string
}

var OfflinePong = UnconnectedPing{
	PingTime: []byte{0, 0, 0, 0, 0, 0, 0, 0},
	ID:       []byte{0, 0, 0, 0, 0, 0, 0, 0},
	Magic:    []byte{0x00, 0xff, 0xff, 0x00, 0xfe, 0xfe, 0xfe, 0xfe, 0xfd, 0xfd, 0xfd, 0xfd, 0x12, 0x34, 0x56, 0x78},
	Pong: PongData{
		Edition:         "MCPE",
		MOTD:            "phantom §cServer offline",
		ProtocolVersion: "390",
		Version:         "1.14.60",
		Players:         "0",
		MaxPlayers:      "0",
		GameType:        "Creative",
		NintendoLimited: "1",
	},
}.Build()

var dupeSemicolonRegex = regexp.MustCompile(";{2,}$")

func ReadUnconnectedPing(in []byte) (reply *UnconnectedPing, err error) {
	reply = &UnconnectedPing{}
	if len(in) < MinHeaderSize {
		return nil, ErrShortHeader
	}

	// Header layout: id(1) | ts(8) | guid(8) | magic(16) | length(2)
	// Copies isolate the caller's buffer from the parsed struct.
	reply.PingTime = make([]byte, 8)
	copy(reply.PingTime, in[1:9])
	reply.ID = make([]byte, 8)
	copy(reply.ID, in[9:17])
	reply.Magic = make([]byte, 16)
	copy(reply.Magic, in[17:33])

	pongLen := int(binary.BigEndian.Uint16(in[33:35]))

	// Fail-fast: a declared payload length longer than what the packet
	// actually contains is a malformed packet, not a partial read.
	if pongLen > len(in)-MinHeaderSize {
		return nil, ErrTruncatedPong
	}

	reply.Pong = readPong(string(in[35 : 35+pongLen]))

	return
}

func (r UnconnectedPing) Build() bytes.Buffer {
	var outBuffer bytes.Buffer

	outBuffer.WriteByte(UnconnectedPongID)
	outBuffer.Write(r.PingTime)
	outBuffer.Write(r.ID)
	outBuffer.Write(r.Magic)

	pongDataString := writePong(r.Pong)
	pongDataLen := len(pongDataString)

	stringBuf := make([]byte, 2)
	binary.BigEndian.PutUint16(stringBuf, uint16(pongDataLen))

	outBuffer.Write(stringBuf)
	outBuffer.WriteString(pongDataString)

	return outBuffer
}

// Reads pong data from the string off the wire into an empty PongData struct
func readPong(raw string) PongData {
	pong := PongData{}
	pongParts := []interface{}{}

	stringParts := strings.Split(raw, ";")
	for _, val := range stringParts {
		pongParts = append(pongParts, val)
	}

	util.MapFieldsToStruct(pongParts, &pong)

	return pong
}

// Turns a PongData into a string that complies with the Bedrock protocol,
// separating the fields with ;
func writePong(pong PongData) string {
	var pongDataFields []string
	pongDataFieldsRaw := util.MapStructToFields(&pong)
	for _, value := range pongDataFieldsRaw {
		stringValue := fmt.Sprintf("%v", value)
		pongDataFields = append(pongDataFields, stringValue)
	}

	// Ensure that there aren't a bunch of ; on the end, but at least one
	joined := strings.Join(pongDataFields, ";")
	joined = dupeSemicolonRegex.ReplaceAllString(joined, "")
	return fmt.Sprintf("%s;", joined)
}
