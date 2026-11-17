package voice

import (
	"errors"
	"fmt"
)

// The one thing the SDK checks about an Opus packet: that it is exactly
// 20 ms. The desktop decoder's output buffer holds 20 ms, so a 40 or 60 ms
// packet fails to decode on every desktop listener (sdk-voice.md section 3).

// opusDurationMicros is the duration of a packet in microseconds, from its
// TOC byte (RFC 6716 section 3.1).
func opusDurationMicros(packet []byte) (int, error) {
	if len(packet) == 0 {
		return 0, errors.New("empty packet")
	}
	toc := packet[0]
	config := int(toc >> 3)
	var frame int
	switch {
	case config <= 11:
		frame = [4]int{10_000, 20_000, 40_000, 60_000}[config%4]
	case config <= 15:
		frame = [2]int{10_000, 20_000}[config%2]
	default:
		frame = [4]int{2_500, 5_000, 10_000, 20_000}[config%4]
	}
	var frames int
	switch toc & 3 {
	case 0:
		frames = 1
	case 1, 2:
		frames = 2
	default:
		if len(packet) < 2 {
			return 0, errors.New("code-3 packet without a frame count")
		}
		frames = int(packet[1] & 0x3f)
	}
	if frames == 0 {
		return 0, errors.New("packet declares zero frames")
	}
	return frame * frames, nil
}

func check20ms(packet []byte) error {
	us, err := opusDurationMicros(packet)
	if err != nil {
		return err
	}
	if us != 20_000 {
		return fmt.Errorf("%g ms", float64(us)/1000)
	}
	return nil
}
