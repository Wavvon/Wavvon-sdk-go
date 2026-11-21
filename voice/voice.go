// Package voice puts a program in a voice channel (sdk-voice.md). It does
// exactly what the desktop and web clients do: voice signalling rides one chat
// WebSocket, the audio rides a WebRTC data channel, and every packet is
// sealed with a per-sender key wrapped to each listener's DH key.
//
// The package owns the mechanisms (key distribution and rotation, 20 ms
// pacing, the replay watermark, the proximity rate limit). It decides nothing
// for the program: mute, deafen, AFK moves and what to do with a changed DH key
// are events and calls. Only a real interop constraint refuses input: an Opus
// packet that is not exactly 20 ms.
//
// Opus passthrough (SendOpus, Audio.Opus) needs no native library. PCM
// (SendPCM, Audio.PCM) needs cgo and libopus: build with -tags opus.
package voice

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	wavvon "github.com/Wavvon/Wavvon-sdk-go"
)

const (
	frame        = 20 * time.Millisecond
	frameSamples = 960
	sampleRate   = 48000
	// A program this far behind is re-anchored instead of bursting to catch up.
	maxLagFrames = 3
	// More than one position every 50 ms risks the hub's silent 30 ms rate drop.
	positionEvery = 50 * time.Millisecond
	speakingIdle  = 200 * time.Millisecond
	stepTimeout   = 15 * time.Second
)

// Options tune Join. Music and Bitrate apply to PCM only.
type Options struct {
	// Music encodes with the audio application instead of voip.
	Music bool
	// Bitrate is the encoder bitrate in bits per second; the encoder's own
	// choice when 0.
	Bitrate int
}

// Participant is someone in the room.
type Participant struct {
	PublicKey   string
	SenderID    uint16
	DisplayName *string
}

// Zone is a proximity zone of the room.
type Zone struct {
	ZoneID string
	Name   string
	// CoordinateSystem is "2d" or "3d".
	CoordinateSystem string
	Attenuation      json.RawMessage
	Positions        map[string][]float64
}

// AudioFrame is one decrypted 20 ms packet from one speaker. Jitter buffering
// is the program's: frames arrive as they come, with TS and Ctr to order by.
type AudioFrame struct {
	From     string
	SenderID uint16
	KeyID    uint32
	// TS is the 48 kHz sample clock, +960 per frame.
	TS      uint32
	Ctr     uint64
	Whisper bool
	Opus    []byte
	// PCM is decoded 48 kHz mono audio; nil unless built with -tags opus.
	PCM []float32
}

// Event is one thing that happened in the room. Type-switch on the concrete
// types below.
type Event interface{ voiceEvent() }

// Audio is a decrypted frame.
type Audio struct{ Frame AudioFrame }

// Roster is who is in the room, after any change.
type Roster struct{ Participants []Participant }

// Speaking says a participant started or stopped transmitting.
type Speaking struct {
	PublicKey string
	Speaking  bool
}

// Zones is the room's zones, after any change.
type Zones struct{ Zones []Zone }

// Position is a participant's new position in a zone.
type Position struct {
	ZoneID    string
	PublicKey string
	Position  []float64
}

// PositionRefused says the hub refused a position update this program sent
// (an unknown zone, or a creator-only zone it did not create). The program
// decides what to do.
type PositionRefused struct{ Reason string }

// TalkGranted says a moderator gave this program the floor; MaySpeak is now true.
type TalkGranted struct{}

// MoveRequested says a moderator, or the AFK sweep (Auto), asks the program to
// move. The hub moves no one: the program decides.
type MoveRequested struct {
	TargetChannelID   string
	TargetChannelName string
	SourceChannelID   string
	EventID           string
	Auto              bool
}

// Rejoining says the socket dropped, which ended the room on the hub; the SDK
// is joining again with a fresh key.
type Rejoining struct{}

// KeySkipped says a participant could not be given this program's key (no DH
// key published, or a changed one), so it cannot hear the program. The same
// event reports a peer whose key could not be unwrapped for the same reason.
type KeySkipped struct {
	PublicKey string
	Reason    string
	Err       error
}

// Unknown is a voice_* message this SDK does not model.
type Unknown struct{ Raw []byte }

// Failure is something that went wrong inside the room that the program
// should know about; the room keeps running unless Err says otherwise.
type Failure struct{ Err error }

func (Audio) voiceEvent()           {}
func (Roster) voiceEvent()          {}
func (Speaking) voiceEvent()        {}
func (Zones) voiceEvent()           {}
func (Position) voiceEvent()        {}
func (PositionRefused) voiceEvent() {}
func (TalkGranted) voiceEvent()     {}
func (MoveRequested) voiceEvent()   {}
func (Rejoining) voiceEvent()       {}
func (KeySkipped) voiceEvent()      {}
func (Unknown) voiceEvent()         {}
func (Failure) voiceEvent()         {}

// Errors.
var (
	// ErrMayNotSpeak: talk power is below the channel's threshold, so the relay
	// would drop every datagram. Lifted by TalkGranted.
	ErrMayNotSpeak = errors.New("voice: may_speak is false in this channel")
	// ErrNotInRoom: after Leave, or between a dropped socket and the rejoin.
	ErrNotInRoom = errors.New("voice: not in a voice room right now")
	// ErrNoPCM: SendPCM without the opus build tag.
	ErrNoPCM = errors.New("voice: PCM needs the opus build tag (cgo and libopus)")
)

// BadFrameError is anything but exactly 20 ms of Opus (or 960 PCM samples).
type BadFrameError struct{ Detail string }

func (e *BadFrameError) Error() string { return "voice: not a single 20 ms frame: " + e.Detail }

// PacketTooLargeError means a packet does not fit a datagram.
type PacketTooLargeError struct{ Size int }

func (e *PacketTooLargeError) Error() string {
	return fmt.Sprintf("voice: a %d-byte packet does not fit a datagram", e.Size)
}

// RefusedError is a refusal from the hub (a failed voice_join, or an error
// frame for another voice message).
type RefusedError struct{ Message string }

func (e *RefusedError) Error() string { return "voice: the hub refused: " + e.Message }

// UnknownZoneError means the zone is not in this room.
type UnknownZoneError struct{ ZoneID string }

func (e *UnknownZoneError) Error() string {
	return fmt.Sprintf("voice: zone %s is not in this room", e.ZoneID)
}

// BadPositionError means the position has the wrong number of coordinates for
// the zone.
type BadPositionError struct{ Got, Want int }

func (e *BadPositionError) Error() string {
	return fmt.Sprintf("voice: position has %d coordinates, the zone takes %d", e.Got, e.Want)
}

type pcmCodec interface {
	encode(frame []float32) ([]byte, error)
	decode(sender uint16, opus []byte) ([]float32, error)
}

type ownKey struct {
	key   [32]byte
	salt  [4]byte
	keyID uint32
	ctr   uint64
}

type remoteID struct {
	pub   string
	keyID uint32
}

type remoteKey struct {
	key  [32]byte
	salt [4]byte
}

type markID struct {
	sender uint16
	keyID  uint32
}

type pacing struct {
	next time.Time
	ts   uint32
}

type pendingPosition struct {
	zoneID   string
	position []float64
}

// Voice is a joined voice room. It is safe for concurrent use: one goroutine
// can call Send* while another reads Events.
type Voice struct {
	client *wavvon.Client
	stream *wavvon.EventStream
	codec  pcmCodec

	ctx    context.Context
	cancel context.CancelFunc
	events chan Event
	q      *queue

	mu           sync.Mutex
	channelID    string
	senderID     uint16
	inRoom       bool
	maySpeak     bool
	muted        bool
	deafened     bool
	roster       map[uint16]Participant
	own          ownKey
	remote       map[remoteID]remoteKey
	marks        map[markID]uint64
	zones        []Zone
	sess         *session
	pace         *pacing
	speaking     bool
	lastSend     time.Time
	position     *pendingPosition
	lastPosition time.Time

	dhMu sync.Mutex
	dh   map[string][32]byte
}

// Join publishes the DH key, joins the channel's voice room and opens the
// audio session. One room per client: the hub allows one per identity.
func Join(ctx context.Context, c *wavvon.Client, channelID string) (*Voice, error) {
	return JoinWith(ctx, c, channelID, Options{})
}

// JoinWith is Join with options.
func JoinWith(ctx context.Context, c *wavvon.Client, channelID string, opts Options) (*Voice, error) {
	if err := c.RequireCapability(ctx, "channels.voice"); err != nil {
		return nil, err
	}
	// Voice transport v3: a hub without it speaks only WebTransport, which
	// this package no longer carries.
	if err := c.RequireCapability(ctx, "voice.webrtc"); err != nil {
		return nil, err
	}
	// Without a published key nobody wraps a voice key to this program and it
	// cannot unwrap theirs: it would be deaf and mute.
	if _, err := c.PublishDHKey(ctx); err != nil {
		return nil, err
	}
	codec, err := newPCM(opts)
	if err != nil {
		return nil, fmt.Errorf("voice: opus codec: %w", err)
	}
	// A socket of its own: the hub ties the room to the connection, so this
	// one carries voice and nothing else the program reads.
	stream := c.Connect(wavvon.EventStreamOptions{})
	vctx, cancel := context.WithCancel(context.Background())
	v := &Voice{
		client: c, stream: stream, codec: codec, ctx: vctx, cancel: cancel,
		events: make(chan Event), q: newQueue(),
		channelID: channelID, maySpeak: true,
		roster: map[uint16]Participant{}, remote: map[remoteID]remoteKey{}, marks: map[markID]uint64{},
		lastSend: time.Now(), lastPosition: time.Now().Add(-positionEvery),
		dh: map[string][32]byte{},
	}
	fail := func(err error) (*Voice, error) {
		cancel()
		stream.Close()
		return nil, err
	}
	if err := v.waitHello(ctx); err != nil {
		return fail(err)
	}
	if err := v.establish(ctx, channelID); err != nil {
		return fail(err)
	}
	go v.pump()
	go v.run()
	go v.housekeeping()
	return v, nil
}

func stepCtx(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(ctx, stepTimeout)
}

func (v *Voice) waitHello(ctx context.Context) error {
	ctx, cancel := stepCtx(ctx)
	defer cancel()
	for {
		ev, err := v.stream.Next(ctx)
		if err != nil {
			return err
		}
		if _, ok := ev.(*wavvon.Hello); ok {
			return nil
		}
	}
}

func str(m map[string]any, k string) string { s, _ := m[k].(string); return s }

func u16(m map[string]any, k string) (uint16, bool) {
	f, ok := m[k].(float64)
	if !ok || f < 0 || f > 65535 || f != float64(uint16(f)) {
		return 0, false
	}
	return uint16(f), true
}

func participant(raw any) (Participant, bool) {
	m, ok := raw.(map[string]any)
	if !ok {
		return Participant{}, false
	}
	pub := str(m, "public_key")
	id, ok := u16(m, "sender_id")
	if pub == "" || !ok {
		return Participant{}, false
	}
	p := Participant{PublicKey: pub, SenderID: id}
	if n, ok := m["display_name"].(string); ok {
		p.DisplayName = &n
	}
	return p, true
}

func participants(raw any) []Participant {
	var out []Participant
	list, _ := raw.([]any)
	for _, x := range list {
		if p, ok := participant(x); ok {
			out = append(out, p)
		}
	}
	return out
}

func floats(raw any) []float64 {
	var out []float64
	list, _ := raw.([]any)
	for _, x := range list {
		if f, ok := x.(float64); ok {
			out = append(out, f)
		}
	}
	return out
}

func zone(raw any) (Zone, bool) {
	m, ok := raw.(map[string]any)
	if !ok || str(m, "zone_id") == "" {
		return Zone{}, false
	}
	z := Zone{ZoneID: str(m, "zone_id"), Name: str(m, "name"), CoordinateSystem: str(m, "coordinate_system"), Positions: map[string][]float64{}}
	z.Attenuation, _ = json.Marshal(m["attenuation"])
	if ps, ok := m["positions"].(map[string]any); ok {
		for k, p := range ps {
			z.Positions[k] = floats(p)
		}
	}
	return z, true
}

func zonesOf(raw any) []Zone {
	var out []Zone
	list, _ := raw.([]any)
	for _, x := range list {
		if z, ok := zone(x); ok {
			out = append(out, z)
		}
	}
	return out
}

func freshKey() (k [32]byte, salt [4]byte) {
	if _, err := rand.Read(k[:]); err != nil {
		panic(err)
	}
	if _, err := rand.Read(salt[:]); err != nil {
		panic(err)
	}
	return
}

// establish is voice_join to an open socket: joined, audio connected, key
// offered. Used for the first join and again after every dropped socket.
func (v *Voice) establish(ctx context.Context, channelID string) error {
	sctx, cancel := stepCtx(ctx)
	defer cancel()
	if err := v.stream.Send(sctx, map[string]string{"type": "voice_join", "channel_id": channelID}); err != nil {
		return err
	}
	var joined map[string]any
	for joined == nil {
		ev, err := v.stream.Next(sctx)
		if err != nil {
			return err
		}
		switch e := ev.(type) {
		case *wavvon.UnknownEvent:
			if e.RawType == "voice_joined" {
				if err := json.Unmarshal(e.Raw, &joined); err != nil {
					return fmt.Errorf("voice: voice_joined did not decode: %w", err)
				}
			}
		case *wavvon.ErrorEvent:
			if e.Context == "voice_join" {
				return &RefusedError{Message: e.Message}
			}
		}
	}
	sess, deferred, err := v.connectTransport(sctx, str(joined, "voice_token"))
	if err != nil {
		return err
	}
	senderID, ok := u16(joined, "sender_id")
	if !ok {
		sess.close("bad join")
		return errors.New("voice: sender_id out of range")
	}

	parts := participants(joined["participants"])
	me := v.client.Identity.PublicKey
	var others []string
	for _, p := range parts {
		if p.PublicKey != me {
			others = append(others, p.PublicKey)
		}
	}
	key, salt := freshKey()
	v.mu.Lock()
	// The key id never goes back: a rejoin must not reuse a (sender, key_id)
	// pair whose replay watermark listeners still hold.
	keyID := v.own.keyID + 1
	if id := str(joined, "channel_id"); id != "" {
		v.channelID = id
	}
	v.senderID = senderID
	v.own = ownKey{key: key, salt: salt, keyID: keyID}
	// A hub without voice.talk omits the field; absence is not "muted".
	v.maySpeak = true
	if b, ok := joined["may_speak"].(bool); ok {
		v.maySpeak = b
	}
	v.roster = map[uint16]Participant{}
	for _, p := range parts {
		v.roster[p.SenderID] = p
	}
	v.remote = map[remoteID]remoteKey{}
	v.marks = map[markID]uint64{}
	v.pace = nil
	v.speaking = false
	v.sess = sess
	v.inRoom = true
	v.mu.Unlock()

	go v.readDatagrams(sess)
	v.offer(others)
	// What arrived while the answer was awaited, a key bundle above all:
	// dropping it would leave this room unable to open that speaker.
	for _, ev := range deferred {
		v.handleEvent(ev)
	}
	return nil
}

// connectTransport offers a WebRTC session bound by the voice token and waits
// for the hub's answer on the same socket, keeping every other event that
// arrives meanwhile.
func (v *Voice) connectTransport(ctx context.Context, token string) (*session, []wavvon.Event, error) {
	offer, err := newRTCOffer()
	if err != nil {
		return nil, nil, fmt.Errorf("voice: transport: %w", err)
	}
	if err := v.stream.Send(ctx, map[string]string{"type": "voice_rtc_offer", "token": token, "sdp": offer.sdp}); err != nil {
		offer.s.close("")
		return nil, nil, err
	}
	var deferred []wavvon.Event
	var answer string
	for answer == "" {
		ev, err := v.stream.Next(ctx)
		if err != nil {
			offer.s.close("")
			return nil, nil, err
		}
		switch e := ev.(type) {
		case *wavvon.UnknownEvent:
			if e.RawType == "voice_rtc_answer" {
				var m map[string]any
				if err := json.Unmarshal(e.Raw, &m); err != nil {
					offer.s.close("")
					return nil, nil, fmt.Errorf("voice: voice_rtc_answer did not decode: %w", err)
				}
				answer = str(m, "sdp")
				continue
			}
		case *wavvon.ErrorEvent:
			if e.Context == "voice_rtc_offer" {
				offer.s.close("")
				return nil, nil, &RefusedError{Message: e.Message}
			}
		}
		deferred = append(deferred, ev)
	}
	sess, err := offer.accept(ctx, answer)
	if err != nil {
		return nil, nil, fmt.Errorf("voice: transport: %w", err)
	}
	return sess, deferred, nil
}

// dhFor is a peer's DH key, looked up once per session: it is pinned, so a
// second answer would be the same or a refusal.
func (v *Voice) dhFor(ctx context.Context, pub string) ([32]byte, error) {
	v.dhMu.Lock()
	k, ok := v.dh[pub]
	v.dhMu.Unlock()
	if ok {
		return k, nil
	}
	k, err := v.client.PeerDHKey(ctx, pub)
	if err != nil {
		return k, err
	}
	v.dhMu.Lock()
	v.dh[pub] = k
	v.dhMu.Unlock()
	return k, nil
}

func perPeer(err error) bool {
	var (
		noKey   *wavvon.RecipientHasNoKeyError
		changed *wavvon.DHKeyChangedError
		unsign  *wavvon.DHKeyUnsignedError
	)
	return errors.As(err, &noKey) || errors.As(err, &changed) || errors.As(err, &unsign)
}

func (v *Voice) emit(ev Event) { v.q.push(ev) }

func (v *Voice) fail(err error) { v.emit(Failure{Err: err}) }

// offer wraps the current sender key to each of to and sends one voice_key_offer.
// A peer without a usable DH key is skipped and reported, as every client does.
func (v *Voice) offer(to []string) {
	if len(to) == 0 {
		return
	}
	v.mu.Lock()
	channel, own := v.channelID, v.own
	v.mu.Unlock()
	go func() {
		var bundles []map[string]string
		for _, pub := range to {
			dh, err := v.dhFor(v.ctx, pub)
			if err != nil {
				if perPeer(err) {
					v.emit(KeySkipped{PublicKey: pub, Reason: err.Error(), Err: err})
					continue
				}
				v.fail(err)
				return
			}
			ct, nonce, err := wavvon.VoiceKeyWrap(v.client.Identity, dh, channel, own.key, own.salt, own.keyID)
			if err != nil {
				v.fail(err)
				continue
			}
			bundles = append(bundles, map[string]string{
				"recipient_pubkey": pub, "ciphertext_hex": hex.EncodeToString(ct), "nonce_hex": hex.EncodeToString(nonce[:]),
			})
		}
		if len(bundles) == 0 {
			return
		}
		err := v.stream.Send(v.ctx, map[string]any{"type": "voice_key_offer", "channel_id": channel, "bundles": bundles})
		if err != nil && v.ctx.Err() == nil {
			v.fail(err)
		}
	}()
}

func (v *Voice) unwrap(m map[string]any) {
	from := str(m, "from_pubkey")
	v.mu.Lock()
	channel := v.channelID
	v.mu.Unlock()
	ct, err1 := hex.DecodeString(str(m, "ciphertext_hex"))
	nonce, err2 := hex.DecodeString(str(m, "nonce_hex"))
	if err1 != nil || err2 != nil || len(nonce) != 12 {
		return
	}
	go func() {
		dh, err := v.dhFor(v.ctx, from)
		if err != nil {
			if perPeer(err) {
				v.emit(KeySkipped{PublicKey: from, Reason: err.Error(), Err: err})
				return
			}
			v.fail(err)
			return
		}
		// A bundle that does not open is dropped: there is no key to use.
		key, salt, keyID, err := wavvon.VoiceKeyUnwrap(v.client.Identity, dh, channel, ct, nonce)
		if err != nil {
			return
		}
		v.mu.Lock()
		defer v.mu.Unlock()
		// A new key for this pair restarts its counter.
		for _, p := range v.roster {
			if p.PublicKey == from {
				delete(v.marks, markID{p.SenderID, keyID})
			}
		}
		v.remote[remoteID{from, keyID}] = remoteKey{key, salt}
	}()
}

func (v *Voice) run() {
	defer v.q.close()
	for {
		ev, err := v.stream.Next(v.ctx)
		if err != nil {
			if v.ctx.Err() == nil && !errors.Is(err, wavvon.ErrStreamClosed) {
				v.fail(err)
			}
			return
		}
		switch e := ev.(type) {
		case *wavvon.Hello:
			v.rejoin()
		default:
			v.handleEvent(e)
		}
	}
}

// rejoin handles a second hello: the socket dropped and came back, so the hub
// already ran leave_voice and the old session is dead. Join again.
func (v *Voice) rejoin() {
	v.mu.Lock()
	v.inRoom = false
	sess, channel := v.sess, v.channelID
	v.sess = nil
	v.mu.Unlock()
	if sess != nil {
		sess.close("rejoin")
	}
	v.emit(Rejoining{})
	if err := v.establish(v.ctx, channel); err != nil && v.ctx.Err() == nil {
		v.fail(err)
	}
}

func (v *Voice) handleEvent(ev wavvon.Event) {
	switch e := ev.(type) {
	case *wavvon.ErrorEvent:
		switch {
		case e.Context == "voice_position_update":
			v.emit(PositionRefused{Reason: e.Message})
		case strings.HasPrefix(e.Context, "voice"):
			v.fail(&RefusedError{Message: e.Context + ": " + e.Message})
		}
	case *wavvon.UnknownEvent:
		if !strings.HasPrefix(e.RawType, "voice_") {
			return
		}
		var m map[string]any
		if json.Unmarshal(e.Raw, &m) != nil {
			return
		}
		v.mu.Lock()
		// Messages about another room are not this session's.
		ours := str(m, "channel_id") == "" || str(m, "channel_id") == v.channelID
		v.mu.Unlock()
		if ours {
			v.handleVoice(e, m, v.client.Identity.PublicKey)
		}
	}
}

func (v *Voice) rosterList() []Participant {
	out := make([]Participant, 0, len(v.roster))
	for _, p := range v.roster {
		out = append(out, p)
	}
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j].SenderID < out[j-1].SenderID; j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	return out
}

func (v *Voice) rotateKey() {
	key, salt := freshKey()
	v.own = ownKey{key: key, salt: salt, keyID: v.own.keyID + 1}
}

func (v *Voice) handleVoice(e *wavvon.UnknownEvent, m map[string]any, me string) {
	switch e.RawType {
	case "voice_participant_joined":
		if p, ok := participant(m["participant"]); ok {
			v.mu.Lock()
			v.roster[p.SenderID] = p
			list := v.rosterList()
			v.mu.Unlock()
			v.emit(Roster{list})
		}
	case "voice_participant_left":
		left := str(m, "public_key")
		v.mu.Lock()
		for id, p := range v.roster {
			if p.PublicKey == left {
				delete(v.roster, id)
				for mk := range v.marks {
					if mk.sender == id {
						delete(v.marks, mk)
					}
				}
			}
		}
		for rk := range v.remote {
			if rk.pub == left {
				delete(v.remote, rk)
			}
		}
		// Whoever left kept the key: a new one for the rest.
		v.rotateKey()
		var remaining []string
		for _, p := range v.roster {
			if p.PublicKey != me {
				remaining = append(remaining, p.PublicKey)
			}
		}
		list := v.rosterList()
		v.mu.Unlock()
		v.emit(Roster{list})
		v.offer(remaining)
	case "voice_roster_update":
		v.mu.Lock()
		v.roster = map[uint16]Participant{}
		for _, p := range participants(m["participants"]) {
			v.roster[p.SenderID] = p
		}
		list := v.rosterList()
		v.mu.Unlock()
		v.emit(Roster{list})
	case "voice_participant_speaking":
		b, _ := m["speaking"].(bool)
		v.emit(Speaking{PublicKey: str(m, "public_key"), Speaking: b})
	case "voice_key_request":
		newcomer := str(m, "new_pubkey")
		if id, ok := u16(m, "new_sender_id"); ok {
			v.mu.Lock()
			if _, there := v.roster[id]; !there {
				v.roster[id] = Participant{PublicKey: newcomer, SenderID: id}
			}
			v.mu.Unlock()
		}
		if newcomer != me {
			v.offer([]string{newcomer})
		}
	case "voice_key_received":
		if id, ok := u16(m, "from_sender_id"); ok {
			v.mu.Lock()
			if _, there := v.roster[id]; !there {
				v.roster[id] = Participant{PublicKey: str(m, "from_pubkey"), SenderID: id}
			}
			v.mu.Unlock()
		}
		v.unwrap(m)
	case "voice_talk_granted":
		if str(m, "public_key") == me {
			v.mu.Lock()
			v.maySpeak = true
			v.mu.Unlock()
			v.emit(TalkGranted{})
		}
	case "voice_move":
		auto, _ := m["auto"].(bool)
		v.emit(MoveRequested{
			TargetChannelID: str(m, "target_channel_id"), TargetChannelName: str(m, "target_channel_name"),
			SourceChannelID: str(m, "source_channel_id"), EventID: str(m, "event_id"), Auto: auto,
		})
	case "voice_zone_state":
		zs := zonesOf(m["zones"])
		v.mu.Lock()
		v.zones = zs
		v.mu.Unlock()
		v.emit(Zones{append([]Zone(nil), zs...)})
	case "voice_zone_created":
		if z, ok := zone(m); ok {
			v.mu.Lock()
			kept := v.zones[:0:0]
			for _, x := range v.zones {
				if x.ZoneID != z.ZoneID {
					kept = append(kept, x)
				}
			}
			v.zones = append(kept, z)
			zs := append([]Zone(nil), v.zones...)
			v.mu.Unlock()
			v.emit(Zones{zs})
		}
	case "voice_zone_destroyed":
		v.mu.Lock()
		kept := v.zones[:0:0]
		for _, x := range v.zones {
			if x.ZoneID != str(m, "zone_id") {
				kept = append(kept, x)
			}
		}
		v.zones = kept
		zs := append([]Zone(nil), kept...)
		v.mu.Unlock()
		v.emit(Zones{zs})
	case "voice_position_updated":
		pos, zoneID, who := floats(m["position"]), str(m, "zone_id"), str(m, "pubkey")
		v.mu.Lock()
		for i := range v.zones {
			if v.zones[i].ZoneID == zoneID {
				// Zones handed out earlier are copies of the slice header only.
				ps := make(map[string][]float64, len(v.zones[i].Positions)+1)
				for k, p := range v.zones[i].Positions {
					ps[k] = p
				}
				ps[who] = pos
				v.zones[i].Positions = ps
			}
		}
		v.mu.Unlock()
		v.emit(Position{ZoneID: zoneID, PublicKey: who, Position: pos})
	case "voice_joined":
	default:
		v.emit(Unknown{Raw: e.Raw})
	}
}

func (v *Voice) readDatagrams(sess *session) {
	for {
		dg, err := sess.ReceiveDatagram(v.ctx)
		if err != nil {
			v.mu.Lock()
			// After leave or during a rejoin the close is ours.
			ours := v.sess == sess && v.inRoom
			if v.sess == sess {
				v.sess = nil
			}
			v.mu.Unlock()
			if ours && v.ctx.Err() == nil {
				v.fail(fmt.Errorf("voice: transport: %w", err))
			}
			return
		}
		v.handleDatagram(dg)
	}
}

// handleDatagram opens one downlink datagram:
// sender_id[2] || packet_type[1] || key_id[4] || ctr[8] || ts[4] || AEAD.
func (v *Voice) handleDatagram(dg []byte) {
	if len(dg) < 3+32 {
		return
	}
	senderID := uint16(dg[0])<<8 | uint16(dg[1])
	whisper := dg[2] == 1
	sealed := dg[3:]
	keyID := uint32(sealed[0])<<24 | uint32(sealed[1])<<16 | uint32(sealed[2])<<8 | uint32(sealed[3])
	var ctr uint64
	for _, b := range sealed[4:12] {
		ctr = ctr<<8 | uint64(b)
	}
	v.mu.Lock()
	if v.deafened {
		v.mu.Unlock()
		return
	}
	p, ok := v.roster[senderID]
	if !ok {
		v.mu.Unlock()
		return
	}
	rk, ok := v.remote[remoteID{p.PublicKey, keyID}]
	if !ok {
		v.mu.Unlock()
		return
	}
	if mark, seen := v.marks[markID{senderID, keyID}]; seen && ctr <= mark {
		v.mu.Unlock()
		return
	}
	// The watermark moves only for a packet that opened: a forged one must
	// not be able to lock the real sender out.
	_, _, ts, opus, err := wavvon.VoicePacketOpen(rk.key, rk.salt, sealed)
	if err != nil {
		v.mu.Unlock()
		return
	}
	v.marks[markID{senderID, keyID}] = ctr
	v.mu.Unlock()
	f := AudioFrame{From: p.PublicKey, SenderID: senderID, KeyID: keyID, TS: ts, Ctr: ctr, Whisper: whisper, Opus: opus}
	if v.codec != nil {
		pcm, err := v.codec.decode(senderID, opus)
		if err != nil {
			v.fail(fmt.Errorf("voice: opus codec: %w", err))
		} else {
			f.PCM = pcm
		}
	}
	v.emit(Audio{f})
}

// housekeeping, every 25 ms: ends a transmission that went quiet, and sends
// the trailing position if one is waiting and the hub's 30 ms limit is safely
// behind.
func (v *Voice) housekeeping() {
	t := time.NewTicker(25 * time.Millisecond)
	defer t.Stop()
	for {
		select {
		case <-v.ctx.Done():
			return
		case <-t.C:
		}
		var msgs []map[string]any
		v.mu.Lock()
		if v.inRoom {
			if v.speaking && time.Since(v.lastSend) > speakingIdle {
				v.speaking = false
				msgs = append(msgs, map[string]any{"type": "voice_speaking", "channel_id": v.channelID, "speaking": false})
			}
			if v.position != nil && time.Since(v.lastPosition) >= positionEvery {
				msgs = append(msgs, map[string]any{"type": "voice_position_update", "zone_id": v.position.zoneID, "position": v.position.position})
				v.position = nil
				v.lastPosition = time.Now()
			}
		}
		v.mu.Unlock()
		for _, m := range msgs {
			if err := v.stream.Send(v.ctx, m); err != nil && v.ctx.Err() == nil {
				v.fail(err)
			}
		}
	}
}

// Events delivers what happens in the room, in order. It is closed after
// Leave. The queue behind it is unbounded: events must be read, or they pile up.
func (v *Voice) Events() <-chan Event { return v.events }

func (v *Voice) pump() {
	defer close(v.events)
	for {
		ev, ok := v.q.pop(v.ctx)
		if !ok {
			return
		}
		select {
		case v.events <- ev:
		case <-v.ctx.Done():
			return
		}
	}
}

// ChannelID is the room's channel (it may differ from the one asked for: a
// spawner room).
func (v *Voice) ChannelID() string {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.channelID
}

// SenderID is this program's relay id in the room.
func (v *Voice) SenderID() uint16 {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.senderID
}

// Roster is who is in the room now.
func (v *Voice) Roster() []Participant {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.rosterList()
}

// Zones is the room's zones now.
func (v *Voice) Zones() []Zone {
	v.mu.Lock()
	defer v.mu.Unlock()
	return append([]Zone(nil), v.zones...)
}

// MaySpeak is false when the relay drops what this program sends; Send* then
// fails with ErrMayNotSpeak until a TalkGranted event.
func (v *Voice) MaySpeak() bool {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.maySpeak
}

// SetMuted is local: the hub has no self-mute. It stops sending (calls to
// Send* still wait their slot and return) and ends the speaking indication.
func (v *Voice) SetMuted(muted bool) {
	v.mu.Lock()
	v.muted = muted
	stop := muted && v.speaking
	channel := v.channelID
	if stop {
		v.speaking = false
	}
	v.mu.Unlock()
	if stop {
		_ = v.stream.Send(v.ctx, map[string]any{"type": "voice_speaking", "channel_id": channel, "speaking": false})
	}
}

// SetDeafened is local: it stops delivering Audio. Key distribution keeps
// running, so undeafening is instant.
func (v *Voice) SetDeafened(deafened bool) {
	v.mu.Lock()
	v.deafened = deafened
	v.mu.Unlock()
}

// SendOpus sends one 20 ms Opus packet, held until its slot on a monotonic
// clock. A source that runs faster than real time is slowed to it; one that
// falls more than three frames behind is re-anchored, ts jumping by the slots
// it missed. A packet that is not exactly 20 ms is refused: desktop
// listeners could not play it.
func (v *Voice) SendOpus(ctx context.Context, packet []byte) error {
	if err := check20ms(packet); err != nil {
		return &BadFrameError{Detail: err.Error()}
	}
	v.mu.Lock()
	if !v.inRoom {
		v.mu.Unlock()
		return ErrNotInRoom
	}
	if !v.maySpeak {
		v.mu.Unlock()
		return ErrMayNotSpeak
	}
	now := time.Now()
	if v.pace == nil {
		v.pace = &pacing{next: now}
	}
	p := v.pace
	if now.After(p.next.Add(frame * maxLagFrames)) {
		missed := uint32(now.Sub(p.next) / frame)
		p.ts += frameSamples * missed
		p.next = now
	}
	slot, ts := p.next, p.ts
	p.next = p.next.Add(frame)
	p.ts += frameSamples
	v.mu.Unlock()

	if d := time.Until(slot); d > 0 {
		t := time.NewTimer(d)
		select {
		case <-t.C:
		case <-ctx.Done():
			t.Stop()
			return ctx.Err()
		}
	}

	v.mu.Lock()
	if !v.inRoom {
		v.mu.Unlock()
		return ErrNotInRoom
	}
	if v.muted {
		v.mu.Unlock()
		return nil
	}
	sess := v.sess
	if sess == nil {
		v.mu.Unlock()
		return ErrNotInRoom
	}
	own := v.own
	v.own.ctr++
	started := !v.speaking
	v.speaking = true
	v.lastSend = time.Now()
	channel := v.channelID
	v.mu.Unlock()

	sealed := wavvon.VoicePacketSeal(own.key, own.salt, own.keyID, own.ctr, ts, packet)
	if started {
		if err := v.stream.Send(ctx, map[string]any{"type": "voice_speaking", "channel_id": channel, "speaking": true}); err != nil {
			return err
		}
	}
	// 3 relay prefix bytes are added by the hub.
	if len(sealed)+3 > maxPacket {
		return &PacketTooLargeError{Size: len(packet)}
	}
	if err := sess.SendDatagram(sealed); err != nil {
		return fmt.Errorf("voice: transport: %w", err)
	}
	return nil
}

// SendPCM sends one 20 ms frame of 48 kHz mono PCM (960 samples), encoded and
// sent as SendOpus. It needs the opus build tag.
func (v *Voice) SendPCM(ctx context.Context, pcm []float32) error {
	if v.codec == nil {
		return ErrNoPCM
	}
	if len(pcm) != frameSamples {
		return &BadFrameError{Detail: fmt.Sprintf("%d samples, not %d", len(pcm), frameSamples)}
	}
	packet, err := v.codec.encode(pcm)
	if err != nil {
		return fmt.Errorf("voice: opus codec: %w", err)
	}
	return v.SendOpus(ctx, packet)
}

// SetPosition sets the latest position in a zone of this room. At most one
// reaches the hub every 50 ms (it silently drops one under 30 ms after the
// last); the newest is always the one sent. The zone and the number of
// coordinates are checked here. A refusal by the hub arrives as PositionRefused.
func (v *Voice) SetPosition(zoneID string, position []float64) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	var z *Zone
	for i := range v.zones {
		if v.zones[i].ZoneID == zoneID {
			z = &v.zones[i]
		}
	}
	if z == nil {
		return &UnknownZoneError{ZoneID: zoneID}
	}
	want := min(max(len(position), 1), 3)
	switch z.CoordinateSystem {
	case "2d":
		want = 2
	case "3d":
		want = 3
	}
	if len(position) != want {
		return &BadPositionError{Got: len(position), Want: want}
	}
	v.position = &pendingPosition{zoneID: zoneID, position: append([]float64(nil), position...)}
	return nil
}

// CreateZone needs channels.manage on the channel. attenuation is the hub's
// {model, max_radius, ref_dist, rolloff} object; nil takes the defaults.
// authMode is "creator_only" or "any_channel_member".
func (v *Voice) CreateZone(ctx context.Context, zoneID, name, coordinateSystem string, attenuation map[string]any, authMode string) error {
	if attenuation == nil {
		attenuation = map[string]any{}
	}
	return v.stream.Send(ctx, map[string]any{
		"type": "voice_zone_create", "zone_id": zoneID, "name": name,
		"coordinate_system": coordinateSystem, "attenuation": attenuation, "auth_mode": authMode,
	})
}

// DestroyZone removes a zone.
func (v *Voice) DestroyZone(ctx context.Context, zoneID string) error {
	return v.stream.Send(ctx, map[string]string{"type": "voice_zone_destroy", "zone_id": zoneID})
}

// Leave sends voice_leave, then closes the audio session and the room's
// socket. Closing the audio session alone would not leave the roster.
func (v *Voice) Leave(ctx context.Context) error {
	v.mu.Lock()
	v.inRoom = false
	channel, wasSpeaking := v.channelID, v.speaking
	sess := v.sess
	v.sess = nil
	v.mu.Unlock()
	var err error
	if wasSpeaking {
		err = v.stream.Send(ctx, map[string]any{"type": "voice_speaking", "channel_id": channel, "speaking": false})
	}
	if lerr := v.stream.Send(ctx, map[string]string{"type": "voice_leave", "channel_id": channel}); err == nil {
		err = lerr
	}
	if sess != nil {
		sess.close("leave")
	}
	// Lets the hub read voice_leave before the socket closes.
	time.Sleep(100 * time.Millisecond)
	v.cancel()
	v.stream.Close()
	return err
}

// queue is an unbounded FIFO: the room must never stall on a slow reader.
type queue struct {
	mu     sync.Mutex
	items  []Event
	wake   chan struct{}
	closed bool
}

func newQueue() *queue { return &queue{wake: make(chan struct{}, 1)} }

func (q *queue) push(ev Event) {
	q.mu.Lock()
	if !q.closed {
		q.items = append(q.items, ev)
	}
	q.mu.Unlock()
	select {
	case q.wake <- struct{}{}:
	default:
	}
}

func (q *queue) close() {
	q.mu.Lock()
	q.closed = true
	q.mu.Unlock()
	select {
	case q.wake <- struct{}{}:
	default:
	}
}

// pop returns the next event, waiting for one. After close it drains what is
// left, then reports false.
func (q *queue) pop(ctx context.Context) (Event, bool) {
	for {
		q.mu.Lock()
		if len(q.items) > 0 {
			ev := q.items[0]
			q.items = q.items[1:]
			q.mu.Unlock()
			return ev, true
		}
		closed := q.closed
		q.mu.Unlock()
		if closed {
			return nil, false
		}
		select {
		case <-q.wake:
		case <-ctx.Done():
			return nil, false
		}
	}
}
