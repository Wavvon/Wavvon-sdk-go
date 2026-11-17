//go:build opus

package voice

import (
	"sync"

	"gopkg.in/hraban/opus.v2"
)

type opusCodec struct {
	encMu sync.Mutex
	enc   *opus.Encoder
	// Decoders are used only from the datagram goroutine.
	decs map[uint16]*opus.Decoder
}

// newPCM builds the encoder (mono, 48 kHz) and an empty decoder set. It needs
// cgo and libopus; build with -tags opus.
func newPCM(opts Options) (pcmCodec, error) {
	app := opus.AppVoIP
	if opts.Music {
		app = opus.AppAudio
	}
	enc, err := opus.NewEncoder(sampleRate, 1, app)
	if err != nil {
		return nil, err
	}
	if opts.Bitrate > 0 {
		if err := enc.SetBitrate(opts.Bitrate); err != nil {
			return nil, err
		}
	}
	return &opusCodec{enc: enc, decs: map[uint16]*opus.Decoder{}}, nil
}

func (c *opusCodec) encode(frame []float32) ([]byte, error) {
	buf := make([]byte, 1275)
	c.encMu.Lock()
	n, err := c.enc.EncodeFloat32(frame, buf)
	c.encMu.Unlock()
	if err != nil {
		return nil, err
	}
	return buf[:n], nil
}

func (c *opusCodec) decode(sender uint16, packet []byte) ([]float32, error) {
	dec, ok := c.decs[sender]
	if !ok {
		var err error
		if dec, err = opus.NewDecoder(sampleRate, 1); err != nil {
			return nil, err
		}
		c.decs[sender] = dec
	}
	pcm := make([]float32, frameSamples)
	n, err := dec.DecodeFloat32(packet, pcm)
	if err != nil {
		return nil, err
	}
	return pcm[:n], nil
}
