package wavvon

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"
)

func TestParseFrameTypesKnownFrames(t *testing.T) {
	e, ok := ParseFrame([]byte(`{"type":"replay_unavailable","earliest_seq":5,"earliest_at":1}`)).(*ReplayUnavailable)
	if !ok || e.EarliestSeq != 5 {
		t.Fatalf("got %#v", e)
	}
	m, ok := ParseFrame([]byte(`{"type":"message_edited","channel_id":"c","message":{"id":"m","content":"hi"}}`)).(*MessageEvent)
	if !ok || m.EventType() != "message_edited" || *m.Message.Content != "hi" {
		t.Fatalf("got %#v", m)
	}
}

func TestParseFrameDeliversUnknownTypesWithTheRawPayload(t *testing.T) {
	raw := `{"type":"voice_zone_created","zone_id":"z"}`
	u, ok := ParseFrame([]byte(raw)).(*UnknownEvent)
	if !ok || u.RawType != "voice_zone_created" || string(u.Raw) != raw {
		t.Fatalf("got %#v", u)
	}
}

func TestParseFrameDeliversGarbageAndMisshapenFramesAsUnknown(t *testing.T) {
	if u, ok := ParseFrame([]byte("{nope")).(*UnknownEvent); !ok || u.RawType != "" {
		t.Fatalf("got %#v", u)
	}
	if u, ok := ParseFrame([]byte(`{"type":"hello","live_seq":"x"}`)).(*UnknownEvent); !ok || u.RawType != "hello" {
		t.Fatalf("got %#v", u)
	}
}

// scriptedHub accepts sockets and hands each one to the test.
type scriptedHub struct {
	conns chan *websocket.Conn
	srv   *httptest.Server
}

func newScriptedHub(t *testing.T) *scriptedHub {
	h := &scriptedHub{conns: make(chan *websocket.Conn, 8)}
	h.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		h.conns <- c
		<-r.Context().Done()
	}))
	t.Cleanup(h.srv.Close)
	return h
}

func (h *scriptedHub) url() string { return "ws" + strings.TrimPrefix(h.srv.URL, "http") }

func (h *scriptedHub) next(t *testing.T) *websocket.Conn {
	t.Helper()
	select {
	case c := <-h.conns:
		return c
	case <-time.After(5 * time.Second):
		t.Fatal("no connection")
		return nil
	}
}

func frame(t *testing.T, c *websocket.Conn, v any) {
	t.Helper()
	b, _ := json.Marshal(v)
	if err := c.Write(context.Background(), websocket.MessageText, b); err != nil {
		t.Fatal(err)
	}
}

func readFrame(t *testing.T, c *websocket.Conn) map[string]any {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, b, err := c.Read(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	_ = json.Unmarshal(b, &m)
	return m
}

func hubEvent(seq int) map[string]any {
	return map[string]any{"type": "hub_event", "seq": seq, "event": "member.joined", "hub_url": "h", "at": 1, "payload": map[string]any{}}
}

func nextEvent(t *testing.T, s *EventStream) Event {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ev, err := s.Next(ctx)
	if err != nil {
		t.Fatal(err)
	}
	return ev
}

type stateLog struct {
	mu sync.Mutex
	s  []ConnectionState
}

func (l *stateLog) add(s ConnectionState) { l.mu.Lock(); l.s = append(l.s, s); l.mu.Unlock() }
func (l *stateLog) get() []ConnectionState {
	l.mu.Lock()
	defer l.mu.Unlock()
	return slices.Clone(l.s)
}

func TestResumesFromTheLastSeqAndDropsReplayDuplicates(t *testing.T) {
	hub := newScriptedHub(t)
	var mu sync.Mutex
	reauths := 0
	s := newEventStream(streamDeps{
		url:    func(context.Context) (string, error) { return hub.url(), nil },
		reauth: func(context.Context) error { mu.Lock(); reauths++; mu.Unlock(); return nil },
		retry:  fast,
	}, EventStreamOptions{})
	defer s.Close()
	states := &stateLog{}
	s.OnStateChange(states.add)

	first := hub.next(t)
	frame(t, first, map[string]any{"type": "hello", "live_seq": 10})
	frame(t, first, hubEvent(11))
	frame(t, first, hubEvent(12))
	var seqs []int64
	for range 3 {
		if e, ok := nextEvent(t, s).(*HubEvent); ok {
			seqs = append(seqs, e.Seq)
		}
	}
	first.Close(websocket.StatusGoingAway, "")

	second := hub.next(t)
	frame(t, second, map[string]any{"type": "hello", "live_seq": 20})
	if got := readFrame(t, second); got["type"] != "resume" || got["since_seq"] != float64(12) {
		t.Fatalf("sent %v", got)
	}
	frame(t, second, hubEvent(12))
	frame(t, second, hubEvent(13))
	frame(t, second, map[string]any{"type": "replay_unavailable", "earliest_seq": 1, "earliest_at": 2})
	sawUnavailable := false
	for !sawUnavailable {
		switch e := nextEvent(t, s).(type) {
		case *HubEvent:
			seqs = append(seqs, e.Seq)
		case *ReplayUnavailable:
			sawUnavailable = true
		}
	}
	if !slices.Equal(seqs, []int64{11, 12, 13}) {
		t.Fatalf("seqs %v", seqs)
	}
	if got := states.get(); !slices.Equal(got, []ConnectionState{ConnOpen, ConnReconnecting, ConnOpen}) {
		t.Fatalf("states %v", got)
	}
	mu.Lock()
	defer mu.Unlock()
	if reauths != 0 {
		t.Fatalf("%d reauths after a greeted connection dropped", reauths)
	}
}

func TestReauthenticatesWhenAConnectionDiesBeforeHello(t *testing.T) {
	hub := newScriptedHub(t)
	reauthed := make(chan struct{}, 4)
	since := int64(4)
	s := newEventStream(streamDeps{
		url:    func(context.Context) (string, error) { return hub.url(), nil },
		reauth: func(context.Context) error { reauthed <- struct{}{}; return nil },
		retry:  fast,
	}, EventStreamOptions{SinceSeq: &since})
	hub.next(t).Close(websocket.StatusGoingAway, "")
	select {
	case <-reauthed:
	case <-time.After(5 * time.Second):
		t.Fatal("no re-authentication")
	}
	c := hub.next(t)
	frame(t, c, map[string]any{"type": "hello", "live_seq": 9})
	if got := readFrame(t, c); got["type"] != "resume" || got["since_seq"] != float64(4) {
		t.Fatalf("sent %v", got)
	}
	s.Close()
	if s.State() != ConnClosed {
		t.Fatalf("state %s", s.State())
	}
	for range 10 {
		if _, err := s.Next(context.Background()); err != nil {
			if err != ErrStreamClosed {
				t.Fatalf("got %v", err)
			}
			return
		}
	}
	t.Fatal("Next after Close must fail once drained")
}
