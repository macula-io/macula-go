package stationlink

import "testing"

// The floor is checked where it is raised, under one lock (WIRE_1_0.md section
// 4.6): a link that completes below the floor another link set meanwhile is
// refused, and leaves the floor where it was.

func TestAHandshakeCompletedBelowTheFloorIsRefusedAndLeavesTheFloor(t *testing.T) {
	f := &handshakeFloors{floor: map[[32]byte]int64{}, counters: map[string]uint64{}}
	station := [32]byte{0x51}
	if !f.completed(station, 6) {
		t.Fatal("the first handshake, version 6, was refused")
	}
	if f.completed(station, 5) {
		t.Error("a version 5 handshake completed below the floor 6")
	}
	if got := f.of(station); got != 6 {
		t.Errorf("floor = %d, want 6", got)
	}
	if got := f.counters["connections"]; got != 1 {
		t.Errorf("connections = %d, want 1: the refused link is not a connection", got)
	}
	if !f.completed(station, 6) {
		t.Error("a handshake at the floor was refused")
	}
}
