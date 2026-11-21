package voice

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/pion/webrtc/v4"
)

// The voice transport (voice-transport-v3.md): one WebRTC data channel,
// negotiated on stream 0, unordered, no retransmission. The hub is ICE-lite
// and answers with its host candidates, so no STUN or TURN server is set.
// The room logic sees only SendDatagram, ReceiveDatagram and close.

// maxPacket fits one SCTP chunk in a 1280-byte path MTU; a larger packet is
// split, and losing any piece loses the frame.
const maxPacket = 1200

type session struct {
	pc   *webrtc.PeerConnection
	dc   *webrtc.DataChannel
	in   chan []byte
	done chan struct{}
	once sync.Once
}

// rtcOffer is a peer with its voice channel, waiting for the hub's answer.
type rtcOffer struct {
	s   *session
	sdp string
}

func newRTCOffer() (*rtcOffer, error) {
	pc, err := webrtc.NewPeerConnection(webrtc.Configuration{})
	if err != nil {
		return nil, err
	}
	negotiated, ordered := true, false
	var id, retransmits uint16 = 0, 0
	dc, err := pc.CreateDataChannel("voice", &webrtc.DataChannelInit{
		Negotiated:     &negotiated,
		ID:             &id,
		Ordered:        &ordered,
		MaxRetransmits: &retransmits,
	})
	if err != nil {
		_ = pc.Close()
		return nil, err
	}
	s := &session{pc: pc, dc: dc, in: make(chan []byte, 256), done: make(chan struct{})}
	pc.OnConnectionStateChange(func(st webrtc.PeerConnectionState) {
		if st == webrtc.PeerConnectionStateFailed || st == webrtc.PeerConnectionStateClosed {
			s.once.Do(func() { close(s.done) })
		}
	})
	dc.OnClose(func() { s.once.Do(func() { close(s.done) }) })
	dc.OnMessage(func(m webrtc.DataChannelMessage) {
		select {
		case s.in <- m.Data:
		default: // a reader that fell behind loses packets, never blocks the channel
		}
	})
	offer, err := pc.CreateOffer(nil)
	if err != nil {
		s.close("")
		return nil, err
	}
	// The offer goes out whole, candidates included: the hub has no trickle.
	gathered := webrtc.GatheringCompletePromise(pc)
	if err := pc.SetLocalDescription(offer); err != nil {
		s.close("")
		return nil, err
	}
	<-gathered
	return &rtcOffer{s: s, sdp: pc.LocalDescription().SDP}, nil
}

// accept applies the hub's answer and waits for the channel to open.
func (o *rtcOffer) accept(ctx context.Context, answer string) (*session, error) {
	open := make(chan struct{})
	o.s.dc.OnOpen(func() { close(open) })
	if err := o.s.pc.SetRemoteDescription(webrtc.SessionDescription{Type: webrtc.SDPTypeAnswer, SDP: answer}); err != nil {
		o.s.close("")
		return nil, err
	}
	select {
	case <-open:
		return o.s, nil
	case <-ctx.Done():
		o.s.close("")
		return nil, fmt.Errorf("voice data channel did not open: %w", ctx.Err())
	}
}

func (s *session) SendDatagram(b []byte) error { return s.dc.Send(b) }

func (s *session) ReceiveDatagram(ctx context.Context) ([]byte, error) {
	select {
	case b := <-s.in:
		return b, nil
	case <-s.done:
		return nil, errClosed
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// errClosed is ReceiveDatagram's answer once the peer connection is gone.
var errClosed = errors.New("voice data channel closed")

func (s *session) close(string) {
	s.once.Do(func() { close(s.done) })
	_ = s.pc.Close()
}
