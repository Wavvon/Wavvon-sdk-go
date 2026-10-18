// Package wavvon is the Go SDK for programs (bots and apps) that talk to a
// Wavvon hub: login that renews itself, the generated REST client, capability
// checks, keyset paging, the WebSocket event stream with resume, app
// registration, and verification of slash-command dispatches and outgoing
// webhooks. The design is sdk.md (tier 1) in Wavvon-docs.
package wavvon

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"reflect"
	"slices"
	"strings"
	"sync"

	"github.com/Wavvon/Wavvon-sdk-go/rest"
)

// SessionState is where the client's REST session is.
type SessionState string

// Session states. StateAuthenticating after StateReady is the reconnecting
// state of REST: a session died and is being re-established.
const (
	StateSignedOut      SessionState = "signed-out"
	StateAuthenticating SessionState = "authenticating"
	StateReady          SessionState = "ready"
)

// ClientOptions configure NewClient. Seed or Identity is required.
type ClientOptions struct {
	HubURL string
	// Seed is a 32-byte Ed25519 seed. It is never sent anywhere.
	Seed []byte
	// Identity is used instead of Seed when set.
	Identity *Identity
	// InviteCode admits the program on an invite_only hub.
	InviteCode string
	Retry      RetryOptions
	// HTTPClient defaults to http.DefaultClient.
	HTTPClient *http.Client
}

// Client is a program's connection to one hub: a session that renews itself,
// the generated REST client, capability checks, app registration and the
// event stream. It is safe for concurrent use.
type Client struct {
	HubURL   string
	Identity *Identity
	// Rest is the client generated from openapi.yaml. Bearer, retry and
	// re-authentication on 401 are built into its transport; pass its
	// results through Check to turn non-2xx answers into errors.
	Rest *rest.ClientWithResponses

	opts    ClientOptions
	http    *http.Client
	loginMu sync.Mutex

	mu       sync.Mutex
	session  *Session
	info     *rest.HubInfo
	state    SessionState
	handlers map[int]func(SessionState)
	nextID   int
}

// NewClient builds a Client. It does not contact the hub.
func NewClient(opts ClientOptions) (*Client, error) {
	c := &Client{
		HubURL:   strings.TrimRight(opts.HubURL, "/"),
		opts:     opts,
		http:     opts.HTTPClient,
		state:    StateSignedOut,
		handlers: map[int]func(SessionState){},
	}
	if c.http == nil {
		c.http = http.DefaultClient
	}
	switch {
	case opts.Identity != nil:
		c.Identity = opts.Identity
	case opts.Seed != nil:
		id, err := IdentityFromSeed(opts.Seed)
		if err != nil {
			return nil, err
		}
		c.Identity = id
	default:
		return nil, errors.New("wavvon: NewClient needs a Seed or an Identity")
	}
	r, err := rest.NewClientWithResponses(c.HubURL, rest.WithHTTPClient(doerFunc(c.do)))
	if err != nil {
		return nil, err
	}
	c.Rest = r
	return c, nil
}

type doerFunc func(*http.Request) (*http.Response, error)

func (f doerFunc) Do(r *http.Request) (*http.Response, error) { return f(r) }

// State is the current session state.
func (c *Client) State() SessionState {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.state
}

// OnStateChange calls fn on every session state change and returns a function
// that stops it. fn runs on the goroutine that caused the change.
func (c *Client) OnStateChange(fn func(SessionState)) (unsubscribe func()) {
	c.mu.Lock()
	defer c.mu.Unlock()
	id := c.nextID
	c.nextID++
	c.handlers[id] = fn
	return func() {
		c.mu.Lock()
		defer c.mu.Unlock()
		delete(c.handlers, id)
	}
}

func (c *Client) setState(s SessionState) {
	c.mu.Lock()
	if c.state == s {
		c.mu.Unlock()
		return
	}
	c.state = s
	fns := make([]func(SessionState), 0, len(c.handlers))
	for _, fn := range c.handlers {
		fns = append(fns, fn)
	}
	c.mu.Unlock()
	for _, fn := range fns {
		fn(s)
	}
}

// Login returns the current session, logging in if there is none.
func (c *Client) Login(ctx context.Context) (Session, error) {
	c.mu.Lock()
	s := c.session
	c.mu.Unlock()
	if s != nil {
		return *s, nil
	}
	return c.relogin(ctx, "")
}

// CanonicalPubkey is the identity the hub attributes this program's actions
// to, or "" before the first login.
func (c *Client) CanonicalPubkey() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.session == nil {
		return ""
	}
	return c.session.CanonicalPubkey
}

// relogin replaces the session whose token was stale, unless another caller
// already did.
func (c *Client) relogin(ctx context.Context, stale string) (Session, error) {
	c.loginMu.Lock()
	defer c.loginMu.Unlock()
	c.mu.Lock()
	s := c.session
	c.mu.Unlock()
	if s != nil && s.Token != stale {
		return *s, nil
	}
	c.setState(StateAuthenticating)
	sess, err := Authenticate(ctx, c.HubURL, c.Identity, AuthOptions{InviteCode: c.opts.InviteCode, Retry: c.opts.Retry, HTTPClient: c.http})
	c.mu.Lock()
	if err != nil {
		c.session = nil
	} else {
		c.session = &sess
	}
	c.mu.Unlock()
	if err != nil {
		c.setState(StateSignedOut)
		return Session{}, err
	}
	c.setState(StateReady)
	return sess, nil
}

// do is the generated client's transport: bearer, retry, one re-login on 401.
func (c *Client) do(req *http.Request) (*http.Response, error) {
	ctx := req.Context()
	if req.Body != nil && req.GetBody == nil {
		b, err := io.ReadAll(req.Body)
		req.Body.Close()
		if err != nil {
			return nil, err
		}
		req.GetBody = func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(b)), nil }
	}
	sess, err := c.Login(ctx)
	if err != nil {
		return nil, err
	}
	res, err := c.send(req, sess.Token)
	if err != nil || res.StatusCode != http.StatusUnauthorized {
		return res, err
	}
	res.Body.Close()
	if sess, err = c.relogin(ctx, sess.Token); err != nil {
		return nil, err
	}
	return c.send(req, sess.Token)
}

func (c *Client) send(req *http.Request, token string) (*http.Response, error) {
	return DoWithRetry(req.Context(), c.opts.Retry, func(ctx context.Context) (*http.Response, error) {
		r := req.Clone(ctx)
		if req.GetBody != nil {
			body, err := req.GetBody()
			if err != nil {
				return nil, err
			}
			r.Body = body
		}
		r.Header.Set("Authorization", "Bearer "+token)
		return c.http.Do(r)
	})
}

// Info returns GET /info, cached after the first call; refresh re-reads it.
func (c *Client) Info(ctx context.Context, refresh bool) (*rest.HubInfo, error) {
	c.mu.Lock()
	info := c.info
	c.mu.Unlock()
	if info != nil && !refresh {
		return info, nil
	}
	res, err := DoWithRetry(ctx, c.opts.Retry, func(ctx context.Context) (*http.Response, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.HubURL+"/info", nil)
		if err != nil {
			return nil, err
		}
		return c.http.Do(req)
	})
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	body, _ := io.ReadAll(res.Body)
	if res.StatusCode != http.StatusOK {
		return nil, &HubError{Status: res.StatusCode, Body: string(body)}
	}
	info = new(rest.HubInfo)
	if err := json.Unmarshal(body, info); err != nil {
		return nil, fmt.Errorf("wavvon: decoding /info: %w", err)
	}
	c.mu.Lock()
	c.info = info
	c.mu.Unlock()
	return info, nil
}

// HasCapability reports whether the hub advertises name. Capabilities, never
// versions.
func (c *Client) HasCapability(ctx context.Context, name string) (bool, error) {
	info, err := c.Info(ctx, false)
	if err != nil {
		return false, err
	}
	return info.Capabilities != nil && slices.Contains(*info.Capabilities, name), nil
}

// RequireCapability returns *UnsupportedByHubError unless the hub advertises name.
func (c *Client) RequireCapability(ctx context.Context, name string) error {
	ok, err := c.HasCapability(ctx, name)
	if err != nil {
		return err
	}
	if !ok {
		return &UnsupportedByHubError{Capability: name}
	}
	return nil
}

// AppProfile is the body of PUT /me/app/profile.
type AppProfile = rest.SetMeAppProfileJSONRequestBody

// AppCommand is one slash command in PUT /me/app/commands.
type AppCommand struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Args        string `json:"args,omitempty"`
	// Scope is "hub" (the default) or "channel".
	Scope      string `json:"scope,omitempty"`
	Privileged bool   `json:"privileged,omitempty"`
	// CooldownSeconds per user and command; nil means the hub default (3), 0 none.
	CooldownSeconds *int64 `json:"cooldown_seconds,omitempty"`
}

// AppSubscription is one entry of PUT /me/app/subscriptions. A message.*
// subscription must name its channels.
type AppSubscription struct {
	Event    string   `json:"event"`
	Channels []string `json:"channels,omitempty"`
}

// SetAppProfile registers or replaces this identity's app profile. Call it
// before Connect: the hub decides whether a socket belongs to an app when it
// connects, and only an app's socket gets hub_event push and resume.
func (c *Client) SetAppProfile(ctx context.Context, profile AppProfile) error {
	if err := c.RequireCapability(ctx, "apps.register"); err != nil {
		return err
	}
	_, err := Check(c.Rest.SetMeAppProfileWithResponse(ctx, profile))
	return err
}

// SetAppCommands replaces this app's slash commands.
func (c *Client) SetAppCommands(ctx context.Context, commands []AppCommand) error {
	return putApp(ctx, c, map[string]any{"commands": nonNil(commands)}, c.Rest.SetMeAppCommandsWithBodyWithResponse)
}

// SetAppSubscriptions replaces this app's event subscriptions.
func (c *Client) SetAppSubscriptions(ctx context.Context, subscriptions []AppSubscription) error {
	return putApp(ctx, c, map[string]any{"subscriptions": nonNil(subscriptions)}, c.Rest.SetMeAppSubscriptionsWithBodyWithResponse)
}

func putApp[R interface{ StatusCode() int }](ctx context.Context, c *Client, body any, call func(context.Context, string, io.Reader, ...rest.RequestEditorFn) (R, error)) error {
	if err := c.RequireCapability(ctx, "apps.register"); err != nil {
		return err
	}
	b, err := json.Marshal(body)
	if err != nil {
		return err
	}
	_, err = Check(call(ctx, "application/json", bytes.NewReader(b)))
	return err
}

func nonNil[T any](s []T) []T {
	if s == nil {
		return []T{}
	}
	return s
}

// PolledEvent is one row of GET /me/events.
type PolledEvent struct {
	ID        string
	EventType string
	// Payload is the event's JSON. A payload that is not JSON arrives as a JSON string.
	Payload   json.RawMessage
	CreatedAt int64
}

// PollEvents reads GET /me/events, the transport for a program that holds no
// socket; since (unix seconds) returns only rows created after it, 0 all.
// Today's hub never writes this queue (Wavvon-server#170): prefer Connect.
func (c *Client) PollEvents(ctx context.Context, since int64) ([]PolledEvent, error) {
	params := &rest.ListMeEventsParams{}
	if since > 0 {
		params.Since = &since
	}
	res, err := Check(c.Rest.ListMeEventsWithResponse(ctx, params))
	if err != nil {
		return nil, err
	}
	if res.JSON200 == nil || res.JSON200.Events == nil {
		return nil, &HubError{Status: res.StatusCode(), Body: "GET /me/events answered without an events array"}
	}
	out := make([]PolledEvent, 0, len(res.JSON200.Events))
	for _, r := range res.JSON200.Events {
		payload := json.RawMessage(r.Payload)
		if !json.Valid(payload) {
			payload, _ = json.Marshal(r.Payload)
		}
		out = append(out, PolledEvent{ID: r.Id, EventType: r.EventType, Payload: payload, CreatedAt: r.CreatedAt})
	}
	return out, nil
}

// AckEvents acknowledges polled events (DELETE /me/events) so they are not
// returned again.
func (c *Client) AckEvents(ctx context.Context, ids []string) error {
	_, err := Check(c.Rest.AckMeEventsWithResponse(ctx, rest.AckMeEventsJSONRequestBody{Ids: &ids}))
	return err
}

// Check passes a generated REST call's result through, turning a non-2xx
// answer into *HubError carrying the hub's own words:
//
//	res, err := wavvon.Check(client.Rest.ListChannelsWithResponse(ctx))
func Check[R interface{ StatusCode() int }](res R, err error) (R, error) {
	if err != nil {
		return res, err
	}
	if s := res.StatusCode(); s < 200 || s > 299 {
		var body string
		if v := reflect.ValueOf(res); v.Kind() == reflect.Pointer && !v.IsNil() {
			if f := v.Elem().FieldByName("Body"); f.IsValid() && f.Kind() == reflect.Slice {
				body = string(f.Bytes())
			}
		}
		return res, &HubError{Status: s, Body: body}
	}
	return res, nil
}
