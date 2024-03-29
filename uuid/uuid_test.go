//
// uuid_test.go
//
// Copyright (c) 2018-2023 Markku Rossi
//
// All rights reserved.
//

package uuid

import (
	"fmt"
	"testing"
)

var uuids = []string{
	"urn:uuid:f81d4fae-7dec-11d0-a765-00a0c91e6bf6",
	"00000000-0000-0000-0000-000000000000",
	"{123e4567-e89b-12d3-a456-426655440000}",
	"792e5b37-4505-47ef-b7d2-8711bb7affa8",
}

func TestParseString(t *testing.T) {
	for _, uuid := range uuids {
		id, err := Parse(uuid)
		if err != nil {
			t.Errorf("Failed to parse UUID %s: %s\n", uuid, err)
		}
		fmt.Printf("UUID: %s\n", id)
	}
}

func FuzzParseStrings(f *testing.F) {
	for _, uuid := range uuids {
		f.Add(uuid)
	}
	f.Fuzz(func(t *testing.T, uuid string) {
		id, err := Parse(uuid)
		if err != nil {
			return
		}
		_ = id
	})
}

func TestSet(t *testing.T) {
	uuid := UUID{}
	id, _ := Parse(uuids[0])
	uuid.Set(id[:])

	if uuid.Compare(id) != 0 {
		t.Errorf("UUID.Set() failed")
	}
}

func TestNew(t *testing.T) {
	id, err := New()
	if err != nil {
		t.Fatalf("Failed to create UUID: %s\n", err)
	}

	_, variant := id.ClkSeqHiAndVariant()
	if variant != RFC4122 {
		t.Errorf("Invalid variant: %d vs. %d", variant, RFC4122)
	}

	if id.Version() != 4 {
		t.Errorf("Invalid version: %d vs. 4", id.Version())
	}
}
