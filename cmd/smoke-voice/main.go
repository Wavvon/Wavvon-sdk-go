// Command smoke-voice exercises voice against a real hub: the owner and a
// second SDK instance share a room, and every assertion needs a decrypted
// frame, never a roster row. Nothing is played; audio stays in memory.
//
//	WAVVON_SMOKE_HUB=http://localhost:3000 [WAVVON_SMOKE_SEED=<64 hex>] go run ./cmd/smoke-voice
//
// The seed identity (default 5a repeated) must be a hub owner: start the hub
// with WAVVON_OWNER_PUBKEY set to its public key. Without cgo the frames are a
// fixed Opus packet and the check is that they arrive intact; build with
// -tags opus (libopus installed) to send a 440 Hz tone through SendPCM and to
// require decoded, non-silent PCM on the other side.
package main

import (
	"context"
	"errors"
	"fmt"
	"math"
	"os"
	"sync"
	"time"

	"github.com/Wavvon/Wavvon-sdk-go/internal/smokeutil"
	"github.com/Wavvon/Wavvon-sdk-go/voice"
)

// A 20 ms CELT fullband packet that decodes to silence.
var silence = []byte{0xF8, 0xFF, 0xFE}

type seen struct {
	mu        sync.Mutex
	frames    map[string]int // "<from>/<key_id>" -> frames
	intact    int
	silentPCM int
	decoded   int
	zones     []string
	positions [][]float64
	refused   []string
	rejoining int
	skipped   int
}

func (s *seen) count(from string, keyID uint32) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.frames[fmt.Sprintf("%s/%d", from, keyID)]
}

func (s *seen) read(f func(*seen) bool) func() bool {
	return func() bool { s.mu.Lock(); defer s.mu.Unlock(); return f(s) }
}

func watch(v *voice.Voice) *seen {
	s := &seen{frames: map[string]int{}}
	go func() {
		for ev := range v.Events() {
			s.mu.Lock()
			switch e := ev.(type) {
			case voice.Audio:
				s.frames[fmt.Sprintf("%s/%d", e.Frame.From, e.Frame.KeyID)]++
				if string(e.Frame.Opus) == string(silence) {
					s.intact++
				}
				if e.Frame.PCM != nil {
					s.decoded++
					var energy float64
					for _, x := range e.Frame.PCM {
						energy += float64(x * x)
					}
					if energy/float64(len(e.Frame.PCM)) < 1e-4 {
						s.silentPCM++
					}
				}
			case voice.Zones:
				s.zones = s.zones[:0]
				for _, z := range e.Zones {
					s.zones = append(s.zones, z.ZoneID)
				}
			case voice.Position:
				s.positions = append(s.positions, e.Position)
			case voice.PositionRefused:
				s.refused = append(s.refused, e.Reason)
			case voice.Rejoining:
				s.rejoining++
			case voice.KeySkipped:
				s.skipped++
			case voice.Failure:
				fmt.Println("voice failure:", e.Err)
			}
			s.mu.Unlock()
		}
	}()
	return s
}

func until(ctx context.Context, what string, ok func() bool) error {
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		if ok() {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(20 * time.Millisecond):
		}
	}
	return fmt.Errorf("timed out waiting for %s", what)
}

// speak sends n frames: a tone through PCM when the build can encode, else the
// fixed packet.
func speak(ctx context.Context, v *voice.Voice, n int) error {
	phase := 0.0
	for range n {
		pcm := make([]float32, 960)
		for i := range pcm {
			pcm[i] = float32(0.5 * math.Sin(phase))
			phase += 2 * math.Pi * 440 / 48000
		}
		err := v.SendPCM(ctx, pcm)
		if errors.Is(err, voice.ErrNoPCM) {
			err = v.SendOpus(ctx, silence)
		}
		if err != nil {
			return err
		}
	}
	return nil
}

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	if err := run(ctx); err != nil {
		fmt.Fprintln(os.Stderr, "VOICE SMOKE FAILED:", err)
		os.Exit(1)
	}
	fmt.Println("VOICE SMOKE OK")
}

func run(ctx context.Context) error {
	hub, err := smokeutil.Hub()
	if err != nil {
		return err
	}
	a, err := smokeutil.Owner(ctx, hub)
	if err != nil {
		return err
	}
	b, err := smokeutil.Join(ctx, hub, a)
	if err != nil {
		return err
	}
	aKey, bKey := a.Identity.PublicKey, b.Identity.PublicKey
	channel, err := smokeutil.VoiceChannel(ctx, a)
	if err != nil {
		return err
	}

	va, err := voice.Join(ctx, a, channel)
	if err != nil {
		return err
	}
	vb, err := voice.Join(ctx, b, channel)
	if err != nil {
		return err
	}
	fmt.Printf("both joined: A is sender %d, B is %d\n", va.SenderID(), vb.SenderID())
	seenA, seenB := watch(va), watch(vb)

	if err := speak(ctx, va, 200); err != nil {
		return err
	}
	if err := until(ctx, "B to receive 100 frames from A", func() bool { return seenB.count(aKey, 1) >= 100 }); err != nil {
		return err
	}
	fmt.Println("B received >= 100 frames from A")
	if err := speak(ctx, vb, 200); err != nil {
		return err
	}
	if err := until(ctx, "A to receive 100 frames from B", func() bool { return seenA.count(bKey, 1) >= 100 }); err != nil {
		return err
	}
	fmt.Println("A received >= 100 frames from B")
	if seenB.read(func(s *seen) bool { return s.decoded > 0 })() {
		if !seenB.read(func(s *seen) bool { return s.silentPCM == 0 })() {
			return errors.New("decoded frames are silent: the tone did not survive")
		}
		fmt.Println("decoded PCM carries the tone")
	} else if !seenB.read(func(s *seen) bool { return s.intact >= 100 })() {
		return errors.New("frames arrived altered")
	}

	var bad *voice.BadFrameError
	if err := va.SendOpus(ctx, []byte{0xF9, 0, 0}); !errors.As(err, &bad) {
		return fmt.Errorf("expected BadFrameError, got %v", err)
	}
	fmt.Println("a 40 ms packet is refused")

	// Rotation: B leaves, so A's key changes to 2; B rejoins and must read it.
	if err := vb.Leave(ctx); err != nil {
		return err
	}
	vb2, err := voice.Join(ctx, b, channel)
	if err != nil {
		return err
	}
	seenB2 := watch(vb2)
	if err := speak(ctx, va, 200); err != nil {
		return err
	}
	if err := until(ctx, "B's second session to read key_id >= 2", func() bool { return seenB2.count(aKey, 2) >= 50 }); err != nil {
		return err
	}
	fmt.Println("after B left, A rotated to key_id >= 2 and B read it")

	// Proximity: ten positions in 100 ms end at the last one.
	if err := va.CreateZone(ctx, "smoke-zone", "smoke", "2d", nil, "any_channel_member"); err != nil {
		return err
	}
	hasZone := func(v *voice.Voice) func() bool {
		return func() bool {
			for _, z := range v.Zones() {
				if z.ZoneID == "smoke-zone" {
					return true
				}
			}
			return false
		}
	}
	if err := until(ctx, "both to see the zone", func() bool { return hasZone(va)() && hasZone(vb2)() }); err != nil {
		return err
	}
	for i := range 10 {
		if err := va.SetPosition("smoke-zone", []float64{10 + float64(i), 50}); err != nil {
			return err
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err := until(ctx, "B to see the last position", seenB2.read(func(s *seen) bool {
		return len(s.positions) > 0 && s.positions[len(s.positions)-1][0] == 19
	})); err != nil {
		return err
	}
	n := seenB2.read(func(s *seen) bool { return len(s.positions) <= 4 })()
	if !n {
		return errors.New("coalescing let more than 4 of 10 positions through")
	}
	fmt.Println("ten positions in 100 ms coalesced, ending at the last")

	// A position in someone else's creator-only zone is refused, as an event.
	if err := va.CreateZone(ctx, "own-zone", "own", "2d", nil, "creator_only"); err != nil {
		return err
	}
	if err := until(ctx, "B to see the creator-only zone", func() bool {
		for _, z := range vb2.Zones() {
			if z.ZoneID == "own-zone" {
				return true
			}
		}
		return false
	}); err != nil {
		return err
	}
	if err := vb2.SetPosition("own-zone", []float64{1, 1}); err != nil {
		return err
	}
	if err := until(ctx, "B to be refused", seenB2.read(func(s *seen) bool { return len(s.refused) > 0 })); err != nil {
		return err
	}
	fmt.Println("B's position was refused:", seenB2.refused[0])

	if !seenA.read(func(s *seen) bool { return s.skipped == 0 && s.rejoining == 0 })() {
		return errors.New("a key was skipped or the room rejoined unexpectedly")
	}
	if err := va.Leave(ctx); err != nil {
		return err
	}
	return vb2.Leave(ctx)
}
