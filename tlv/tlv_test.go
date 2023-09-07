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
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
	"testing"
)

func TestTags(t *testing.T) {
	key := uint32(1 << 31)
	for i := 0; i <= 32; i++ {
		values := Values{
			Type(key): key,
		}
		data, err := values.Marshal()
		if err != nil {
			t.Fatalf("Marshal type %d failed: %s\n", key, err)
		}
		if false {
			fmt.Printf("Encoded:\n%s", hex.Dump(data))
		}

		decoded, err := Unmarshal(data)
		if err != nil {
			t.Fatalf("Unmarshal type %d failed: %s\n", key, err)
		}
		val, ok := decoded[Type(key)]
		if !ok {
			t.Fatalf("Decoded values does not contain key")
		}
		ival, ok := val.(uint32)
		if !ok {
			t.Fatalf("Invalid value type %T", val)
		}
		if ival != key {
			t.Fatalf("Invalid value: got %d, expected %d", ival, key)
		}

		key >>= 1
	}
}

func TestMarshal(t *testing.T) {
	values := Values{
		Type(0): uint8(8),
		Type(1): uint16(16),
		Type(2): uint32(32),
		Type(3): uint64(64),
		Type(4): "foo",
		Type(5): Values{
			Type(3): uint32(0),
		},
		Type(6): true,
		Type(7): false,
		Type(8): []byte{1, 2, 3, 4},
	}

	data, err := values.Marshal()
	if err != nil {
		t.Fatalf("Marshal failed: %s\n", err)
	}
	fmt.Printf("Data:\n%s", hex.Dump(data))

	decoded, err := Unmarshal(data)
	if err != nil {
		t.Fatalf("Unmarshal failed: %s\n", err)
	}
	fmt.Printf("Decoded: %v\n", decoded)

	for k, v := range values {
		dval, ok := decoded[k]
		if !ok {
			t.Fatalf("Decoded does not contain key %v\n", k)
		}
		switch eval := v.(type) {
		case Values:
			deval, ok := dval.(Values)
			if !ok {
				t.Fatalf("Failed: %v, %v\n", eval, deval)
			}

		case []byte:
			deval, ok := dval.([]byte)
			if !ok {
				t.Fatalf("Failed: %v, %v\n", eval, deval)
			}
			if bytes.Compare(eval, deval) != 0 {
				t.Fatalf("Data mismatch: %x != %x", eval, deval)
			}

		default:
			if v != dval {
				t.Fatalf("Value mismatch: got %v, expected %v\n", dval, v)
			}
		}
	}
}

func FuzzMarshal(f *testing.F) {
	testcases := []Values{
		{
			Type(0): uint8(8),
		},
		{
			Type(4): "Hello, world!",
		},
		{
			Type(4): "Hello, outer!",
			Type(5): Values{
				Type(3): uint32(0),
				Type(4): "Hello, inner!",
			},
		},
		{
			Type(6): true,
		},
		{
			Type(8): []byte{1, 2, 3, 4},
		},
	}
	for _, tc := range testcases {
		data, err := tc.Marshal()
		if err != nil {
			f.Fatalf("Marshal failed: %s\n", err)
		}
		f.Add(data)
	}

	f.Fuzz(func(t *testing.T, orig []byte) {
		_, err := Unmarshal(orig)
		if err != nil {
			fmt.Printf("Unmarshal failed: %v\n", err)
		}
	})
}

var token = "BCkSC01GLWpDOHRJRkpRGgtYbFB4OWZ1bXhLZyEIAAAAAF4jM9wsAwABAQtATFNxfKFwTMhuP3RBVpoQN_DigoNxZhdgAyueEjc9NNdglZLkIAVuEiOv52w3snPQ5VtcRo8cRAOc8XsnolB3Cw"

func TestDump(t *testing.T) {
	data, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil {
		t.Fatalf("Failed to decode token: %s", err)
	}
	values, err := Unmarshal(data)
	if err != nil {
		t.Fatalf("TLV unmarshal: %s", err)
	}
	values.Dump(os.Stdout, Symtab{
		0: Symbol{
			Name: "values",
			Child: Symtab{
				2: Symbol{
					Name: "tenant_id",
				},
				3: Symbol{
					Name: "client_id",
				},
				4: Symbol{
					Name: "created",
				},
				5: Symbol{
					Name: "scope",
					Child: Symtab{
						0: Symbol{
							Name: "admin",
						},
					},
				},
			},
		},
		1: Symbol{
			Name: "signature",
		},
	})
}
