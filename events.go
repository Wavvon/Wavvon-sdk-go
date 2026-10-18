package wavvon

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"

	"github.com/Wavvon/Wavvon-sdk-go/rest"
	"github.com/coder/websocket"
)

// Event is one server-to-client WebSocket frame (ws-protocol.md, checked
// against Wavvon-server crates/hub/src/routes/chat_models.rs). Type-switch on
// the concrete types below; a frame this version does not model arrives as
// *UnknownEvent, never dropped.
type Event interface {
	// EventType is the frame's "type" field ("binary" for a binary frame).
	EventType() string
}

// Hello is the first frame on every connection.
type Hello struct {
	LiveSeq int64 `json:"live_seq"`
}

// ErrorEvent reports a failed client frame.
type ErrorEvent struct {
	Context string `json:"context"`
	Message string `json:"message"`
}

// Pong answers a ping (capability ws.ping).
type Pong struct {
	Nonce           int64    `json:"nonce"`
	OutboundLossPct *float64 `json:"outbound_loss_pct,omitempty"`
}

// MessageEvent is a new ("message") or edited ("message_edited") channel message.
type MessageEvent struct {
	Type      string       `json:"type"`
	ChannelID string       `json:"channel_id"`
	Message   rest.Message `json:"message"`
}

// MessageRefEvent is "message_deleted", "message_pinned" or "message_unpinned".
type MessageRefEvent struct {
	Type      string `json:"type"`
	ChannelID string `json:"channel_id"`
	MessageID string `json:"message_id"`
}

// ReactionsUpdated carries a message's full reaction list.
type ReactionsUpdated struct {
	ChannelID string `json:"channel_id"`
	MessageID string `json:"message_id"`
	Reactions []struct {
		Emoji string `json:"emoji"`
		Count int    `json:"count"`
		Me    bool   `json:"me"`
	} `json:"reactions"`
}

// TypingEvent says someone started or stopped typing in a channel.
type TypingEvent struct {
	ChannelID   string  `json:"channel_id"`
	PublicKey   string  `json:"public_key"`
	DisplayName *string `json:"display_name"`
	Typing      bool    `json:"typing"`
}

// DMEvent is a direct message notification.
type DMEvent struct {
	ConversationID string  `json:"conversation_id"`
	Sender         string  `json:"sender"`
	SenderName     *string `json:"sender_name"`
	Content        string  `json:"content"`
	Timestamp      int64   `json:"timestamp"`
}

// HubEvent is the one envelope for live push, replay and outgoing webhooks
// (apps.md §5).
type HubEvent struct {
	Seq int64 `json:"seq"`
	// Event is e.g. "member.joined", "message.created".
	Event   string         `json:"event"`
	HubURL  string         `json:"hub_url"`
	At      int64          `json:"at"`
	Payload map[string]any `json:"payload"`
	// Replay only, and only when the audit row has them.
	ActorPubkey  string `json:"actor_pubkey,omitempty"`
	TargetPubkey string `json:"target_pubkey,omitempty"`
	ChannelID    string `json:"channel_id,omitempty"`
	Replayed     bool   `json:"replayed,omitempty"`
}

// ReplayComplete ends a resume replay.
type ReplayComplete struct {
	Replayed    int64 `json:"replayed"`
	LiveFromSeq int64 `json:"live_from_seq"`
}

// ReplayUnavailable means the resume point is older than the hub keeps
// (72 hours): events between it and EarliestSeq are lost to this program.
type ReplayUnavailable struct {
	EarliestSeq int64 `json:"earliest_seq"`
	EarliestAt  int64 `json:"earliest_at"`
}

// AppLaunch is a mini-app launch card in a channel.
type AppLaunch struct {
	AppID       string `json:"app_id"`
	Title       string `json:"title"`
	Description string `json:"description"`
	ChannelID   string `json:"channel_id"`
}

// AppOpen tells a player's client to open a mini-app.
type AppOpen struct {
	AppID          string `json:"app_id"`
	ChannelID      string `json:"channel_id"`
	MiniAppURL     string `json:"mini_app_url"`
	SessionToken   string `json:"session_token"`
	RequiresCamera bool   `json:"requires_camera"`
}

// AppClose ends a mini-app session.
type AppClose struct {
	AppID     string `json:"app_id"`
	ChannelID string `json:"channel_id"`
}

// MiniAppMessage is an opaque payload relayed between a mini-app host and a
// player; FromPubkey names the player on the host side.
type MiniAppMessage struct {
	AppID      string `json:"app_id"`
	ChannelID  string `json:"channel_id"`
	Payload    string `json:"payload"`
	FromPubkey string `json:"from_pubkey,omitempty"`
}

// UnknownEvent is a frame of a type this SDK does not model, or one that did
// not decode. Never swallowed.
type UnknownEvent struct {
	// RawType is the frame's own type, "binary" for a binary frame, "" if unparseable.
	RawType string
	Raw     []byte
}

func (*Hello) EventType() string             { return "hello" }
func (*ErrorEvent) EventType() string        { return "error" }
func (*Pong) EventType() string              { return "pong" }
func (e *MessageEvent) EventType() string    { return e.Type }
func (e *MessageRefEvent) EventType() string { return e.Type }
func (*ReactionsUpdated) EventType() string  { return "reactions_updated" }
func (*TypingEvent) EventType() string       { return "typing" }
func (*DMEvent) EventType() string           { return "dm" }
func (*HubEvent) EventType() string          { return "hub_event" }
func (*ReplayComplete) EventType() string    { return "replay_complete" }
func (*ReplayUnavailable) EventType() string { return "replay_unavailable" }
func (*AppLaunch) EventType() string         { return "app_launch" }
func (*AppOpen) EventType() string           { return "app_open" }
func (*AppClose) EventType() string          { return "app_close" }
func (*MiniAppMessage) EventType() string    { return "mini_app_message" }
func (e *UnknownEvent) EventType() string    { return e.RawType }

var frameTypes = map[string]func() Event{
	"hello":              func() Event { return new(Hello) },
	"error":              func() Event { return new(ErrorEvent) },
	"pong":               func() Event { return new(Pong) },
	"message":            func() Event { return new(MessageEvent) },
	"message_edited":     func() Event { return new(MessageEvent) },
	"message_deleted":    func() Event { return new(MessageRefEvent) },
	"message_pinned":     func() Event { return new(MessageRefEvent) },
	"message_unpinned":   func() Event { return new(MessageRefEvent) },
	"reactions_updated":  func() Event { return new(ReactionsUpdated) },
	"typing":             func() Event { return new(TypingEvent) },
	"dm":                 func() Event { return new(DMEvent) },
	"hub_event":          func() Event { return new(HubEvent) },
	"replay_complete":    func() Event { return new(ReplayComplete) },
	"replay_unavailable": func() Event { return new(ReplayUnavailable) },
	"app_launch":         func() Event { return new(AppLaunch) },
	"app_open":           func() Event { return new(AppOpen) },
	"app_close":          func() Event { return new(AppClose) },
	"mini_app_message":   func() Event { return new(MiniAppMessage) },
}

// ParseFrame turns one text frame into a typed event. A frame of an unknown
// type, or one whose fields do not decode, is an *UnknownEvent.
func ParseFrame(data []byte) Event {
	var head struct {
		Type string `json:"type"`
	}
	if err := json.Unmarshal(data, &head); err != nil {
		return &UnknownEvent{Raw: data}
	}
	if mk, ok := frameTypes[head.Type]; ok {
		ev := mk()
		if json.Unmarshal(data, ev) == nil {
			return ev
		}
	}
	return &UnknownEvent{RawType: head.Type, Raw: data}
}

// ConnectionState is where an EventStream's socket is.
type ConnectionState string

// Connection states.
const (
	ConnConnecting   ConnectionState = "connecting"
	ConnOpen         ConnectionState = "open"
	ConnReconnecting ConnectionState = "reconnecting"
	ConnClosed       ConnectionState = "closed"
)

// EventStreamOptions configure Connect.
type EventStreamOptions struct {
	// SinceSeq replays hub events after this seq on the first connect (an app
	// persisting its position across restarts). Nil starts from now.
	SinceSeq *int64
	// Buffer is how many events wait for Next before reading pauses. Default 256.
	Buffer int
}

type streamDeps struct {
	url    func(context.Context) (string, error)
	reauth func(context.Context) error
	retry  RetryOptions
	http   *http.Client
}

// EventStream is one hub WebSocket that reconnects on its own. It tracks the
// last hub_event seq and sends resume after every reconnect, so an app misses
// nothing inside the hub's 72-hour window; ReplayUnavailable is delivered like
// any other event when it falls outside. Events a replay repeats (seq not
// above the last one seen) are dropped.
type EventStream struct {
	deps   streamDeps
	ctx    context.Context
	cancel context.CancelFunc
	events chan Event
	done   chan struct{}

	mu       sync.Mutex
	conn     *websocket.Conn
	state    ConnectionState
	lastSeq  *int64
	handlers map[int]func(ConnectionState)
	nextID   int
}

// Connect opens the hub WebSocket and keeps it open, re-authenticating and
// resuming on its own, until Close. Call SetAppProfile first: the hub only
// pushes and replays hub events on a socket opened by a registered app.
func (c *Client) Connect(opts EventStreamOptions) *EventStream {
	return newEventStream(streamDeps{
		url: func(ctx context.Context) (string, error) {
			s, err := c.Login(ctx)
			if err != nil {
				return "", err
			}
			ws := "ws" + strings.TrimPrefix(c.HubURL, "http")
			return ws + "/ws?token=" + url.QueryEscape(s.Token), nil
		},
		reauth: func(ctx context.Context) error {
			c.mu.Lock()
			stale := ""
			if c.session != nil {
				stale = c.session.Token
			}
			c.mu.Unlock()
			_, err := c.relogin(ctx, stale)
			return err
		},
		retry: c.opts.Retry,
		http:  c.http,
	}, opts)
}

func newEventStream(deps streamDeps, opts EventStreamOptions) *EventStream {
	buf := opts.Buffer
	if buf <= 0 {
		buf = 256
	}
	ctx, cancel := context.WithCancel(context.Background())
	s := &EventStream{
		deps: deps, ctx: ctx, cancel: cancel,
		events:   make(chan Event, buf),
		done:     make(chan struct{}),
		state:    ConnConnecting,
		lastSeq:  opts.SinceSeq,
		handlers: map[int]func(ConnectionState){},
	}
	go s.run()
	return s
}

// Next blocks until the next event, ctx ends, or the stream is closed
// (ErrStreamClosed).
func (s *EventStream) Next(ctx context.Context) (Event, error) {
	select {
	case ev, ok := <-s.events:
		if !ok {
			return nil, ErrStreamClosed
		}
		return ev, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// State is the socket's current state.
func (s *EventStream) State() ConnectionState {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.state
}

// LastSeq is the highest hub_event seq seen (or the hub's live seq at first
// connect); persist it and pass it as SinceSeq to resume after a restart.
func (s *EventStream) LastSeq() (seq int64, ok bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.lastSeq == nil {
		return 0, false
	}
	return *s.lastSeq, true
}

// OnStateChange calls fn on every state change and returns a function that
// stops it. fn runs on the stream's goroutine; keep it short.
func (s *EventStream) OnStateChange(fn func(ConnectionState)) (unsubscribe func()) {
	s.mu.Lock()
	defer s.mu.Unlock()
	id := s.nextID
	s.nextID++
	s.handlers[id] = fn
	return func() {
		s.mu.Lock()
		defer s.mu.Unlock()
		delete(s.handlers, id)
	}
}

func (s *EventStream) setState(st ConnectionState) {
	s.mu.Lock()
	if s.state == st || s.state == ConnClosed {
		s.mu.Unlock()
		return
	}
	s.state = st
	fns := make([]func(ConnectionState), 0, len(s.handlers))
	for _, fn := range s.handlers {
		fns = append(fns, fn)
	}
	s.mu.Unlock()
	for _, fn := range fns {
		fn(st)
	}
}

// Send writes one client frame (any JSON-encodable value with a "type").
// It fails unless the socket is open.
func (s *EventStream) Send(ctx context.Context, frame any) error {
	s.mu.Lock()
	conn, state := s.conn, s.state
	s.mu.Unlock()
	if state == ConnClosed {
		return ErrStreamClosed
	}
	if conn == nil || state != ConnOpen {
		return fmt.Errorf("wavvon: socket is %s, not open", state)
	}
	b, err := json.Marshal(frame)
	if err != nil {
		return err
	}
	return conn.Write(ctx, websocket.MessageText, b)
}

// Subscribe asks for a channel's live frames (messages, typing).
func (s *EventStream) Subscribe(ctx context.Context, channelID string) error {
	return s.Send(ctx, map[string]string{"type": "subscribe", "channel_id": channelID})
}

// AnnounceApp is the mini-app host showing a launch card in a channel.
// Players' app_join is answered by the hub, not by the host.
func (s *EventStream) AnnounceApp(ctx context.Context, channelID, title, description string) error {
	return s.Send(ctx, map[string]string{"type": "app_announce", "channel_id": channelID, "title": title, "description": description})
}

// DismissApp is the mini-app host closing the session; clients dismiss their webviews.
func (s *EventStream) DismissApp(ctx context.Context, channelID string) error {
	return s.Send(ctx, map[string]string{"type": "app_dismiss", "channel_id": channelID})
}

// SendMiniAppMessage relays an opaque payload to one joined player's
// mini-app. Players' messages arrive as *MiniAppMessage with FromPubkey.
func (s *EventStream) SendMiniAppMessage(ctx context.Context, appID, channelID, toPubkey, payload string) error {
	return s.Send(ctx, map[string]string{"type": "mini_app_message", "app_id": appID, "channel_id": channelID, "payload": payload, "to_pubkey": toPubkey})
}

// Close stops the stream and waits for its goroutine. Next then returns
// ErrStreamClosed once buffered events are drained.
func (s *EventStream) Close() {
	s.setState(ConnClosed)
	s.cancel()
	<-s.done
}

func (s *EventStream) run() {
	defer close(s.done)
	defer close(s.events)
	attempt := 0
	for {
		greeted := s.connectOnce()
		if s.ctx.Err() != nil {
			return
		}
		s.setState(ConnReconnecting)
		if greeted {
			attempt = 0
		}
		attempt++
		if s.deps.retry.wait(s.ctx, s.deps.retry.Backoff(attempt)) != nil {
			return
		}
		if !greeted {
			// A refused upgrade and a dropped one look alike; a fresh
			// session costs one login and rules out a dead token.
			_ = s.deps.reauth(s.ctx)
		}
	}
}

// connectOnce runs one connection to its end and reports whether the hub
// said hello on it.
func (s *EventStream) connectOnce() (greeted bool) {
	u, err := s.deps.url(s.ctx)
	if err != nil {
		return false
	}
	conn, _, err := websocket.Dial(s.ctx, u, &websocket.DialOptions{HTTPClient: s.deps.http})
	if err != nil {
		return false
	}
	conn.SetReadLimit(16 << 20)
	s.mu.Lock()
	s.conn = conn
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		s.conn = nil
		s.mu.Unlock()
		conn.CloseNow()
	}()
	for {
		typ, data, err := conn.Read(s.ctx)
		if err != nil {
			return greeted
		}
		var ev Event
		if typ == websocket.MessageBinary {
			ev = &UnknownEvent{RawType: "binary", Raw: data}
		} else {
			ev = ParseFrame(data)
		}
		switch e := ev.(type) {
		case *Hello:
			greeted = true
			s.mu.Lock()
			resumeFrom := s.lastSeq
			if resumeFrom == nil {
				live := e.LiveSeq
				s.lastSeq = &live
			}
			s.mu.Unlock()
			s.setState(ConnOpen)
			if resumeFrom != nil {
				b, _ := json.Marshal(map[string]any{"type": "resume", "since_seq": *resumeFrom})
				if conn.Write(s.ctx, websocket.MessageText, b) != nil {
					return greeted
				}
			}
		case *HubEvent:
			// Live events that arrived during a replay are flushed after it
			// and can repeat what the replay already carried.
			s.mu.Lock()
			dup := s.lastSeq != nil && e.Seq <= *s.lastSeq
			if !dup {
				seq := e.Seq
				s.lastSeq = &seq
			}
			s.mu.Unlock()
			if dup {
				continue
			}
		}
		select {
		case s.events <- ev:
		case <-s.ctx.Done():
			return greeted
		}
	}
}
