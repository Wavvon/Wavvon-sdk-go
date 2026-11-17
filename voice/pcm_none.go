//go:build !opus

package voice

// Without the opus build tag the SDK links no codec: SendOpus and the Opus
// field of Audio work, SendPCM and Audio.PCM do not.
func newPCM(Options) (pcmCodec, error) { return nil, nil }
