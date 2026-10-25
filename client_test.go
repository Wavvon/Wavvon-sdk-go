package wavvon

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
)

// fakeHub has a token that can be revoked mid-run and a flaky /channels.
type fakeHub struct {
	mu           sync.Mutex
	capabilities []string
	tokens       int
	valid        string
	flaky        int
	log          []string
	events       string
}

func (h *fakeHub) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.log = append(h.log, r.Method+" "+r.URL.Path)
	switch r.URL.Path {
	case "/info":
		_ = json.NewEncoder(w).Encode(map[string]any{"public_key": "aa", "capabilities": h.capabilities})
		return
	case "/auth/challenge":
		_ = json.NewEncoder(w).Encode(map[string]string{"challenge": strings.Repeat("00", 32), "scheme": "tagged-v1"})
		return
	case "/auth/verify":
		h.tokens++
		h.valid = fmt.Sprintf("t%d", h.tokens)
		_ = json.NewEncoder(w).Encode(map[string]string{"token": h.valid, "scope": "member", "canonical_pubkey": "me"})
		return
	}
	if r.Header.Get("Authorization") != "Bearer "+h.valid {
		http.Error(w, "expired", http.StatusUnauthorized)
		return
	}
	switch {
	case r.URL.Path == "/channels" && h.flaky > 0:
		h.flaky--
		w.WriteHeader(http.StatusTooManyRequests)
	case r.URL.Path == "/me/app/commands":
		w.WriteHeader(http.StatusOK)
	case r.URL.Path == "/me/events" && r.URL.Query().Get("cursor") == "1":
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusGone)
		_, _ = w.Write([]byte(`{"type":"replay_unavailable","earliest_seq":40,"earliest_at":9}`))
	case r.URL.Path == "/me/events":
		h.log = append(h.log, "cursor="+r.URL.Query().Get("cursor"))
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(h.events))
	default:
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode([]map[string]string{{"id": "c1", "name": "general"}})
	}
}

func (h *fakeHub) set(f func()) {
	h.mu.Lock()
	defer h.mu.Unlock()
	f()
}

func (h *fakeHub) count(entry string) int {
	h.mu.Lock()
	defer h.mu.Unlock()
	n := 0
	for _, l := range h.log {
		if l == entry {
			n++
		}
	}
	return n
}

func newTestClient(t *testing.T, h *fakeHub, retry RetryOptions) *Client {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	c, err := NewClient(ClientOptions{HubURL: srv.URL, Seed: make([]byte, 32), Retry: retry})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestBearerAndOneReloginOn401(t *testing.T) {
	h := &fakeHub{}
	c := newTestClient(t, h, fast)
	var states []SessionState
	c.OnStateChange(func(s SessionState) { states = append(states, s) })
	ctx := context.Background()
	res, err := Check(c.Rest.ListChannelsWithResponse(ctx))
	if err != nil || res.JSON200 == nil || len(*res.JSON200) != 1 {
		t.Fatalf("got %v, %v", res, err)
	}
	h.set(func() { h.valid = "revoked" })
	if _, err := Check(c.Rest.ListChannelsWithResponse(ctx)); err != nil {
		t.Fatal(err)
	}
	if n := h.count("POST /auth/verify"); n != 2 {
		t.Fatalf("%d logins", n)
	}
	want := []SessionState{StateAuthenticating, StateReady, StateAuthenticating, StateReady}
	if !slices.Equal(states, want) {
		t.Fatalf("states %v", states)
	}
}

func TestRetries429AndFailsLoudlyWhenTheBudgetIsSpent(t *testing.T) {
	h := &fakeHub{}
	r := fast
	r.MaxAttempts = 3
	c := newTestClient(t, h, r)
	ctx := context.Background()
	h.set(func() { h.flaky = 2 })
	if _, err := Check(c.Rest.ListChannelsWithResponse(ctx)); err != nil {
		t.Fatal(err)
	}
	h.set(func() { h.flaky = 10 })
	_, err := Check(c.Rest.ListChannelsWithResponse(ctx))
	var hu *HubUnavailableError
	if !errors.As(err, &hu) {
		t.Fatalf("got %v", err)
	}
}

func TestAppRegistrationIsGatedOnTheCapability(t *testing.T) {
	ctx := context.Background()
	without := newTestClient(t, &fakeHub{}, fast)
	err := without.SetAppCommands(ctx, nil)
	var ue *UnsupportedByHubError
	if !errors.Is(err, ErrUnsupportedByHub) || !errors.As(err, &ue) || ue.Capability != "apps.register" {
		t.Fatalf("got %v", err)
	}
	h := &fakeHub{capabilities: []string{"apps.register"}}
	with := newTestClient(t, h, fast)
	if err := with.SetAppCommands(ctx, []AppCommand{{Name: "echo", Description: "Echo"}}); err != nil {
		t.Fatal(err)
	}
	if h.count("PUT /me/app/commands") != 1 {
		t.Fatal("PUT /me/app/commands not sent")
	}
}

func TestPollEventsPagesBySeqAndReportsAGoneCursor(t *testing.T) {
	h := &fakeHub{events: `[{"type":"hub_event","seq":42,"event":"member.joined","hub_url":"h","at":1,"payload":{"a":1},"replayed":true}]`}
	c := newTestClient(t, h, fast)
	got, err := c.PollEvents(context.Background(), 41, 0)
	if err != nil || len(got) != 1 || got[0].Seq != 42 || got[0].Payload["a"] != float64(1) {
		t.Fatalf("got %+v, %v", got, err)
	}
	if h.count("cursor=41") != 1 {
		t.Fatal("cursor not sent")
	}
	var gone *ReplayUnavailableError
	if _, err := c.PollEvents(context.Background(), 1, 0); !errors.As(err, &gone) || gone.EarliestSeq != 40 {
		t.Fatalf("want ReplayUnavailableError, got %v", err)
	}
	h.set(func() { h.events = `{}` })
	if _, err := c.PollEvents(context.Background(), 0, 0); err == nil {
		t.Fatal("a body that is not an array must not read as no events")
	}
}
