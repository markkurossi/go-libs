//
// uuid.go
//
// Copyright (c) 2018 Markku Rossi
//
// All rights reserved.
//

package uuid

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
)

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

type UUID [16]byte

type Variant uint8

const (
	ReservedNCS Variant = iota
	RFC4122
	Microsoft
	ReservedFuture
)

// Nil UUID is a special case UUID which has all bits set to zero.
var Nil UUID

var reUUID = regexp.MustCompile("^(urn:uuid:)?([[:xdigit:]]{8})-([[:xdigit:]]{4})-([[:xdigit:]]{4})-([[:xdigit:]]{4})-([[:xdigit:]]{12})$")

func (id UUID) String() string {
	return fmt.Sprintf("%0x-%0x-%0x-%0x-%0x",
		id[0:4], id[4:6], id[6:8], id[8:10], id[10:16])
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

func (id UUID) Node() []byte {
	return id[10:16]
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

	return id, nil
}
