//
// tlv.go
//
// Copyright (c) 2019-2023 Markku Rossi
//
// All rights reserved.
//

package tlv

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sort"
)

var (
	bo = binary.BigEndian

	// ErrorTruncated is returned if the binary data does not contain
	// specified number of elements in the TLV's length encoding.
	ErrorTruncated = errors.New("truncated data")

	// ErrorEOF is returned if an unexpected EOF is encountered.
	ErrorEOF = errors.New("unexpected EOF")
)

// Type specifies TLV types.
type Type uint32

// Values specify a collection of key-value pairs.
type Values map[Type]interface{}

// Keys returns the keys in sorted order.
func (v Values) Keys() []Type {
	keys := make([]Type, len(v))
	i := 0
	for key := range v {
		keys[i] = key
		i++
	}
	sort.Slice(keys, func(i, j int) bool {
		return keys[i] < keys[j]
	})
	return keys
}

// Symtab specifies mapping from types to their names.
type Symtab map[Type]Symbol

// Symbol specifies a symtab entry.
type Symbol struct {
	Name  string
	Child Symtab
}

// Dump prints the value to the specified writer. The Symtab argument
// specifies type names.
func (v Values) Dump(w io.Writer, s Symtab) {
	v.dump(w, s, 0)
}

func (v Values) dump(w io.Writer, s Symtab, indent int) {
	for _, t := range v.Keys() {
		var child Symtab

		symbol, ok := s[t]

		v.prefix(w, indent)
		if ok {
			fmt.Fprintf(w, "%s: ", symbol.Name)
			child = symbol.Child
		} else {
			fmt.Fprintf(w, "%d: ", t)
		}
		switch val := v[t].(type) {
		case string:
			fmt.Fprintf(w, "%q", val)

		case []byte:
			fmt.Fprintf(w, "%x", val)

		case Values:
			fmt.Fprintf(w, "{\n")
			val.dump(w, child, indent+1)

			v.prefix(w, indent)
			fmt.Fprintf(w, "}")

		default:
			fmt.Fprintf(w, "%v", val)
		}
		fmt.Fprintf(w, "\n")
	}
}

func (v Values) prefix(w io.Writer, indent int) {
	for i := 0; i < indent; i++ {
		fmt.Fprintf(w, "    ")
	}
}

// VType defines value type.
type VType uint8

// Value types.
const (
	VTBool VType = iota
	VTInt
	VTString
	VTData
	VTMap
)

var vtypes = map[VType]string{
	VTBool:   "bool",
	VTInt:    "int",
	VTString: "string",
	VTData:   "data",
	VTMap:    "map",
}

func (vt VType) String() string {
	name, ok := vtypes[vt]
	if ok {
		return name
	}
	return fmt.Sprintf("{VType %d}", vt)
}

// Tag defines value's type and value type.
type Tag uint64

// Type returns the type of the tag.
func (t Tag) Type() Type {
	return Type(t >> 3)
}

// SetType sets the type of the tag.
func (t *Tag) SetType(val Type) {
	*t = Tag(val)<<3 | Tag(*t&0x7)
}

// VType returns the type of the tag value.
func (t Tag) VType() VType {
	return VType(t & 0x7)
}

// SetVType sets the type of the tag value.
func (t *Tag) SetVType(val VType) {
	*t = Tag(*t&^0x7) | Tag(val)
}

func (t Tag) String() string {
	return fmt.Sprintf("%s: %d", t.VType(), t.Type())
}

// Marshal encodes the values into binary TLV-encoding.
func (v Values) Marshal() ([]byte, error) {
	buf := new(bytes.Buffer)
	var tmp [8]byte

	for _, key := range v.Keys() {
		var tag Tag

		tag.SetType(key)

		switch val := v[key].(type) {
		case bool:
			tag.SetVType(VTBool)
			marshalInt(uint64(tag), buf)
			buf.WriteByte(1)
			if val {
				buf.WriteByte(1)
			} else {
				buf.WriteByte(0)
			}

		case uint8:
			tag.SetVType(VTInt)
			marshalInt(uint64(tag), buf)
			buf.WriteByte(1)
			buf.WriteByte(byte(val))

		case uint16:
			tag.SetVType(VTInt)
			marshalInt(uint64(tag), buf)
			marshalInt(2, buf)
			bo.PutUint16(tmp[:], uint16(val))
			buf.Write(tmp[:2])

		case uint32:
			tag.SetVType(VTInt)
			marshalInt(uint64(tag), buf)
			marshalInt(4, buf)
			bo.PutUint32(tmp[:], uint32(val))
			buf.Write(tmp[:4])

		case uint64:
			tag.SetVType(VTInt)
			marshalInt(uint64(tag), buf)
			marshalInt(8, buf)
			bo.PutUint64(tmp[:], uint64(val))
			buf.Write(tmp[:8])

		case string:
			tag.SetVType(VTString)
			marshalInt(uint64(tag), buf)
			data := []byte(val)
			marshalInt(uint64(len(data)), buf)
			buf.Write(data)

		case []byte:
			tag.SetVType(VTData)
			marshalInt(uint64(tag), buf)
			marshalInt(uint64(len(val)), buf)
			buf.Write(val)

		case Values:
			tag.SetVType(VTMap)
			marshalInt(uint64(tag), buf)
			d, err := val.Marshal()
			if err != nil {
				return nil, err
			}
			marshalInt(uint64(len(d)), buf)
			buf.Write(d)

		default:
			return nil, fmt.Errorf("type %T (val=%v) not supported", val, val)
		}
	}

	return buf.Bytes(), nil
}

// Unmarshal decodes the TLV-encoded data.
func Unmarshal(data []byte) (Values, error) {
	result := make(Values)
	ofs := 0

	var ival, length uint64
	var err error

	for ofs < len(data) {
		ival, ofs, err = unmarshalInt(data, ofs)
		if err != nil {
			return nil, err
		}
		tag := Tag(ival)
		length, ofs, err = unmarshalInt(data, ofs)
		if err != nil {
			return nil, err
		}

		var val interface{}

		if ofs+int(length) > len(data) {
			return nil, ErrorTruncated
		}

		switch tag.VType() {
		case VTBool:
			if data[ofs] != 0 {
				val = true
			} else {
				val = false
			}

		case VTInt:
			switch length {
			case 1:
				val = uint8(data[ofs])

			case 2:
				val = bo.Uint16(data[ofs:])

			case 4:
				val = bo.Uint32(data[ofs:])

			case 8:
				val = bo.Uint64(data[ofs:])

			default:
				return nil, fmt.Errorf("invalid integer data length %d", length)
			}

		case VTString:
			val = string(data[ofs : ofs+int(length)])

		case VTData:
			val = data[ofs : ofs+int(length)]

		case VTMap:
			val, err = Unmarshal(data[ofs : ofs+int(length)])
			if err != nil {
				return nil, err
			}

		default:
			return nil, fmt.Errorf("invalid value type %s", tag.VType())
		}
		ofs += int(length)

		result[tag.Type()] = val
	}

	return result, nil
}

func marshalInt(val uint64, buf *bytes.Buffer) {
	mask := uint64(0x7f << 28)

	i := 4

	// Skip zero septets.
	for ; i > 0; i-- {
		masked := val & mask
		if masked != 0 {
			break
		}
		mask >>= 7
	}
	// Write value septets.
	for ; i >= 0; i-- {
		masked := val & mask
		masked >>= uint64(i * 7)
		if i > 0 {
			masked |= 0x80
		}
		buf.WriteByte(byte(masked))
		mask >>= 7
	}
}

func unmarshalInt(data []byte, ofs int) (uint64, int, error) {
	// Read max 5 bytes.
	var result uint64
	for i := 0; i < 5; i++ {
		if ofs >= len(data) {
			return 0, ofs, ErrorEOF
		}
		bit := data[ofs] & 0x80
		val := data[ofs] & 0x7f

		ofs++

		result <<= 7
		result |= uint64(val)

		if bit == 0 {
			return result, ofs, nil
		}
	}
	return 0, ofs, ErrorEOF
}
