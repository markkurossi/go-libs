//
// uuid.go
//
// Copyright (c) 2018 Markku Rossi
//
// All rights reserved.
//

// Package uuid implements Universally Unique Identifier (UUID)
// handling, as specified by RFC 4122.
package uuid

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
)

// UUID is an Universally Unique IDentifier, as defined by RFC
// 4122. The UUID represents the UUID in its binary encoding. The RFC
// 4122 specifies the encoding and fields as follows.
//
// The fields are encoded as 16 octets, with the sizes and order of the
// fields defined above, and with each field encoded with the Most
// Significant Byte first (known as network byte order).  Note that the
// field names, particularly for multiplexed fields, follow historical
// practice.
//
// 0                   1                   2                   3
//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                          time_low                             |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |       time_mid                |         time_hi_and_version   |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |clk_seq_hi_res |  clk_seq_low  |         node (0-1)            |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                         node (2-5)                            |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
// If the UUID variant is `Microsoft', the first 3 elements are
// encoded in little-endian format. This has practially no affect
// unless you have to match ASCII and binary UUIDs in which case the
// equality differs between variants.
type UUID [16]byte

type Variant uint8

const (
	ReservedNCS Variant = iota
	RFC4122
	Microsoft
	ReservedFuture
)

var variants = map[Variant]string{
	ReservedNCS:    "Reserved, NCS",
	RFC4122:        "RFC 4122",
	Microsoft:      "Microsoft",
	ReservedFuture: "Reserved, future",
}

func (v Variant) String() string {
	name, ok := variants[v]
	if ok {
		return name
	}
	return fmt.Sprintf("{Variant %d}", v)
}

// Nil UUID is a special case UUID which has all bits set to zero.
var Nil UUID

// {urn:uuid:f81d4fae-7dec-11d0-a765-00a0c91e6bf6}
var reUUID = regexp.MustCompile("^\\{?(urn:uuid:)?([[:xdigit:]]{8})-([[:xdigit:]]{4})-([[:xdigit:]]{4})-([[:xdigit:]]{4})-([[:xdigit:]]{12})\\}?$")

func (id UUID) String() string {
	return fmt.Sprintf("%08x-%04x-%04x-%0x-%0x",
		id.TimeLow(), id.TimeMid(), id.TimeHiAndVersion(), id[8:10], id[10:16])
}

func (id UUID) TimeLow() uint32 {
	_, variant := id.ClkSeqHiAndVariant()
	if variant == Microsoft {
		return binary.LittleEndian.Uint32(id[0:4])
	} else {
		return binary.BigEndian.Uint32(id[0:4])
	}
}

func (id UUID) TimeMid() uint16 {
	_, variant := id.ClkSeqHiAndVariant()
	if variant == Microsoft {
		return binary.LittleEndian.Uint16(id[4:6])
	} else {
		return binary.BigEndian.Uint16(id[4:6])
	}
}

func (id UUID) TimeHiAndVersion() uint16 {
	_, variant := id.ClkSeqHiAndVariant()
	if variant == Microsoft {
		return binary.LittleEndian.Uint16(id[6:8])
	} else {
		return binary.BigEndian.Uint16(id[6:8])
	}
}

func (id UUID) Time() uint64 {
	return (uint64(id.TimeHiAndVersion()&0x0f) << 48) |
		uint64(id.TimeMid()<<32) |
		uint64(id.TimeLow())
}

func (id UUID) Version() uint8 {
	return uint8(id.TimeHiAndVersion() >> 12)
}

func (id UUID) ClkSeqHiAndVariant() (uint8, Variant) {
	val := id[8]
	if (val & 0x80) == 0 {
		return val & 0x7f, ReservedNCS
	}
	if (val & 0xc0) == 0x80 {
		return val & 0x3f, RFC4122
	}
	if (val & 0xe0) == 0xc0 {
		return val & 0x1f, Microsoft
	}
	return val & 0x1f, ReservedFuture
}

func (id UUID) ClkSeqLow() uint8 {
	return id[9]
}

func (id UUID) ClkSeq() uint16 {
	hi, _ := id.ClkSeqHiAndVariant()
	return uint16(hi)<<8 | uint16(id.ClkSeqLow())
}

func (id UUID) Node() []byte {
	return id[10:16]
}

// Set sets the UUIDs content from the raw binary data.
func (id *UUID) Set(data []byte) {
	copy(id[:], data)
}

func (id UUID) Compare(id2 UUID) int {
	if id.TimeLow() < id2.TimeLow() {
		return -1
	} else if id.TimeLow() > id2.TimeLow() {
		return 1
	}

	if id.TimeMid() < id2.TimeMid() {
		return -1
	} else if id.TimeMid() > id2.TimeMid() {
		return 1
	}

	if id.TimeHiAndVersion() < id2.TimeHiAndVersion() {
		return -1
	} else if id.TimeHiAndVersion() > id2.TimeHiAndVersion() {
		return 1
	}

	v1, _ := id.ClkSeqHiAndVariant()
	v2, _ := id2.ClkSeqHiAndVariant()
	if v1 < v2 {
		return -1
	} else if v1 > v2 {
		return 1
	}

	if id.ClkSeqLow() < id2.ClkSeqLow() {
		return -1
	} else if id.ClkSeqLow() > id2.ClkSeqLow() {
		return 1
	}

	return bytes.Compare(id.Node(), id2.Node())
}

func Parse(value string) (UUID, error) {
	m := reUUID.FindStringSubmatch(value)
	if m == nil {
		return Nil, errors.New("Invalid UUID format")
	}

	data, err := hex.DecodeString(m[2] + m[3] + m[4] + m[5] + m[6])
	if err != nil {
		return Nil, err
	}

	id := UUID{}
	copy(id[:], data)

	_, variant := id.ClkSeqHiAndVariant()
	if variant == Microsoft {
		v32 := binary.BigEndian.Uint32(id[0:4])
		binary.LittleEndian.PutUint32(id[0:4], v32)

		v16 := binary.BigEndian.Uint16(id[4:6])
		binary.LittleEndian.PutUint16(id[4:6], v16)

		v16 = binary.BigEndian.Uint16(id[6:8])
		binary.LittleEndian.PutUint16(id[6:8], v16)
	}

	return id, nil
}

func MustParse(value string) UUID {
	id, err := Parse(value)
	if err != nil {
		panic(fmt.Sprintf("Failed to parse UUID %s: %s\n", value, err))
	}
	return id
}

func ParseData(data []byte) (UUID, error) {
	if len(data) != 16 {
		return Nil, errors.New("Invalid data length")
	}

	id := UUID{}
	id.Set(data)

	return id, nil
}

// New returns new version 4 UUID (random UUID).
func New() (UUID, error) {
	id := UUID{}
	_, err := rand.Read(id[:])
	if err != nil {
		return Nil, err
	}

	// Variant: RFC4122
	id[8] = 0x80 | (id[8] & 0x3f)

	// Version: 4
	id[6] = 0x40 | (id[6] & 0x0f)

	return id, nil
}
