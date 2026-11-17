package voice

import (
	"context"
	"errors"
	"testing"
	"time"

	wavvon "github.com/Wavvon/Wavvon-sdk-go"
)

func TestOpusToCDurations(t *testing.T) {
	for _, c := range []struct {
		packet []byte
		us     int
	}{
		{[]byte{0x08}, 20_000},     // SILK NB 20 ms
		{[]byte{0xF8}, 20_000},     // CELT FB 20 ms
		{[]byte{0xF0}, 10_000},     // CELT FB 10 ms
		{[]byte{0xF9}, 40_000},     // two frames
		{[]byte{0x1B, 3}, 180_000}, // 60 ms x 3
		{[]byte{0x78}, 20_000},     // hybrid FB 20 ms
	} {
		if got, err := opusDurationMicros(c.packet); err != nil || got != c.us {
			t.Errorf("%x: got %d, %v; want %d", c.packet, got, err, c.us)
		}
	}
}

func TestOnlyTwentyMillisecondsPasses(t *testing.T) {
	for _, ok := range [][]byte{{0xF8, 1, 2}} {
		if err := check20ms(ok); err != nil {
			t.Errorf("%x refused: %v", ok, err)
		}
	}
	for _, bad := range [][]byte{{0xF0}, {0xFB, 2}, {}, {0xFB}, {0xFB, 0}} {
		if check20ms(bad) == nil {
			t.Errorf("%x passed", bad)
		}
	}
	var v Voice
	var bf *BadFrameError
	if err := v.SendOpus(context.Background(), []byte{0xF9, 0, 0}); !errors.As(err, &bf) {
		t.Fatalf("a 40 ms packet: %v", err)
	}
}

func listener(t *testing.T) (*Voice, [32]byte, [4]byte) {
	t.Helper()
	v := &Voice{
		q: newQueue(), roster: map[uint16]Participant{7: {PublicKey: "speaker", SenderID: 7}},
		remote: map[remoteID]remoteKey{}, marks: map[markID]uint64{},
	}
	key, salt := [32]byte{1, 2, 3}, [4]byte{9, 8, 7, 6}
	v.remote[remoteID{"speaker", 1}] = remoteKey{key, salt}
	return v, key, salt
}

func downlink(sender uint16, whisper byte, sealed []byte) []byte {
	return append([]byte{byte(sender >> 8), byte(sender), whisper}, sealed...)
}

func drain(v *Voice) []Event {
	v.q.mu.Lock()
	defer v.q.mu.Unlock()
	out := v.q.items
	v.q.items = nil
	return out
}

func TestDatagramsAreOpenedOnceAndForgeriesDoNotMoveTheWatermark(t *testing.T) {
	v, key, salt := listener(t)
	opus := []byte{0xF8, 1, 2, 3}
	at := func(ctr uint64) []byte {
		return downlink(7, 0, wavvon.VoicePacketSeal(key, salt, 1, ctr, uint32(ctr)*960, opus))
	}

	v.handleDatagram(at(5))
	evs := drain(v)
	if len(evs) != 1 {
		t.Fatalf("got %d events", len(evs))
	}
	a := evs[0].(Audio).Frame
	if a.From != "speaker" || a.Ctr != 5 || a.TS != 5*960 || string(a.Opus) != string(opus) || a.Whisper {
		t.Fatalf("frame: %+v", a)
	}

	v.handleDatagram(at(5))
	v.handleDatagram(at(4))
	if len(drain(v)) != 0 {
		t.Fatal("a replayed or older counter was delivered")
	}

	forged := at(900)
	forged[len(forged)-1] ^= 1
	v.handleDatagram(forged)
	if len(drain(v)) != 0 {
		t.Fatal("a forged packet was delivered")
	}
	v.handleDatagram(at(6))
	if len(drain(v)) != 1 {
		t.Fatal("a forgery locked the real sender out")
	}

	wrongKey := downlink(7, 0, wavvon.VoicePacketSeal([32]byte{9}, salt, 1, 7, 0, opus))
	v.handleDatagram(wrongKey)
	unknownKeyID := downlink(7, 0, wavvon.VoicePacketSeal(key, salt, 2, 8, 0, opus))
	v.handleDatagram(unknownKeyID)
	unknownSender := downlink(8, 0, wavvon.VoicePacketSeal(key, salt, 1, 9, 0, opus))
	v.handleDatagram(unknownSender)
	if len(drain(v)) != 0 {
		t.Fatal("a packet under the wrong key, key id or sender was delivered")
	}

	v.deafened = true
	v.handleDatagram(at(10))
	if len(drain(v)) != 0 {
		t.Fatal("audio was delivered while deafened")
	}
	v.deafened = false
	v.handleDatagram(downlink(7, 1, wavvon.VoicePacketSeal(key, salt, 1, 11, 0, opus)))
	if evs := drain(v); len(evs) != 1 || !evs[0].(Audio).Frame.Whisper {
		t.Fatal("a whisper packet was not flagged")
	}
}

func TestPositionChecksZoneAndArity(t *testing.T) {
	v := &Voice{zones: []Zone{{ZoneID: "z2", CoordinateSystem: "2d"}, {ZoneID: "z3", CoordinateSystem: "3d"}}}
	var uz *UnknownZoneError
	if err := v.SetPosition("nope", []float64{1, 2}); !errors.As(err, &uz) {
		t.Fatalf("unknown zone: %v", err)
	}
	var bp *BadPositionError
	if err := v.SetPosition("z2", []float64{1, 2, 3}); !errors.As(err, &bp) || bp.Want != 2 {
		t.Fatalf("arity: %v", err)
	}
	if err := v.SetPosition("z3", []float64{1, 2, 3}); err != nil {
		t.Fatal(err)
	}
	if err := v.SetPosition("z3", []float64{4, 5, 6}); err != nil || v.position.position[0] != 4 {
		t.Fatalf("only the newest position is kept: %v", err)
	}
}

func TestPositionRefusedIsAnEventNotAFailure(t *testing.T) {
	v := &Voice{q: newQueue()}
	v.handleEvent(&wavvon.ErrorEvent{Context: "voice_position_update", Message: "Only the zone creator can move in this zone."})
	v.handleEvent(&wavvon.ErrorEvent{Context: "voice_zone_create", Message: "no"})
	evs := drain(v)
	if len(evs) != 2 {
		t.Fatalf("got %d events", len(evs))
	}
	if r, ok := evs[0].(PositionRefused); !ok || r.Reason != "Only the zone creator can move in this zone." {
		t.Fatalf("first: %#v", evs[0])
	}
	var refused *RefusedError
	if f, ok := evs[1].(Failure); !ok || !errors.As(f.Err, &refused) {
		t.Fatalf("second: %#v", evs[1])
	}
}

func TestQueueIsUnboundedOrderedAndDrainsAfterClose(t *testing.T) {
	q := newQueue()
	for i := range 1000 {
		q.push(Position{ZoneID: "z", Position: []float64{float64(i)}})
	}
	q.close()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	for i := range 1000 {
		ev, ok := q.pop(ctx)
		if !ok || ev.(Position).Position[0] != float64(i) {
			t.Fatalf("event %d: %v %v", i, ev, ok)
		}
	}
	if _, ok := q.pop(ctx); ok {
		t.Fatal("pop after drain and close returned an event")
	}
}
