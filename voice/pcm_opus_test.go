//go:build opus

package voice

import (
	"math"
	"testing"
)

func TestPCMRoundTripThroughLibopus(t *testing.T) {
	c, err := newPCM(Options{})
	if err != nil {
		t.Fatal(err)
	}
	var phase float64
	var last []float32
	for range 10 {
		pcm := make([]float32, frameSamples)
		for i := range pcm {
			pcm[i] = float32(0.5 * math.Sin(phase))
			phase += 2 * math.Pi * 440 / sampleRate
		}
		packet, err := c.encode(pcm)
		if err != nil {
			t.Fatal(err)
		}
		if err := check20ms(packet); err != nil {
			t.Fatalf("the encoder produced a packet that is not 20 ms: %v", err)
		}
		if last, err = c.decode(3, packet); err != nil {
			t.Fatal(err)
		}
	}
	var energy float64
	for _, x := range last {
		energy += float64(x * x)
	}
	if len(last) != frameSamples || energy/frameSamples < 1e-3 {
		t.Fatalf("decoded %d samples with mean energy %g", len(last), energy/frameSamples)
	}
}
