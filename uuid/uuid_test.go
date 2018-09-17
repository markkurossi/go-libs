//
// uuid_test.go
//
// Copyright (c) 2018 Markku Rossi
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

func TestSet(t *testing.T) {
	uuid := UUID{}
	id, _ := Parse(uuids[0])
	uuid.Set(id[:])

	if uuid.Compare(id) != 0 {
		t.Errorf("UUID.Set() failed")
	}
}
