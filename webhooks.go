package wavvon

import (
	"context"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/hkdf"
)

// Wire shapes from Wavvon-server crates/hub/src/routes/app_models.rs.

// AuthorInfo names who invoked a command or pressed a component.
type AuthorInfo struct {
	Pubkey      string `json:"pubkey"`
	DisplayName string `json:"display_name,omitempty"`
}

// Dispatch is a verified webhook call from the hub: *SlashInvocation,
// *ComponentInteraction, or *UnknownDispatch for a type this SDK does not know.
type Dispatch interface {
	DispatchType() string
}

// SlashInvocation is a slash command a member ran.
type SlashInvocation struct {
	HubURL        string     `json:"hub_url"`
	ChannelID     string     `json:"channel_id"`
	MessageIDHint string     `json:"message_id_hint"`
	Author        AuthorInfo `json:"author"`
	Command       string     `json:"command"`
	ArgsRaw       string     `json:"args_raw"`
	ArgsTokens    []string   `json:"args_tokens"`
}

// ComponentInteraction is a button press or select choice on an app's message.
type ComponentInteraction struct {
	HubURL    string     `json:"hub_url"`
	ChannelID string     `json:"channel_id"`
	MessageID string     `json:"message_id"`
	CustomID  string     `json:"custom_id"`
	Values    []string   `json:"values"`
	User      AuthorInfo `json:"user"`
}

// UnknownDispatch is a verified dispatch whose type this SDK does not know.
// Delivered, never dropped.
type UnknownDispatch struct {
	RawType string
	Raw     json.RawMessage
}

func (*SlashInvocation) DispatchType() string      { return "slash_command" }
func (*ComponentInteraction) DispatchType() string { return "component_interaction" }
func (u *UnknownDispatch) DispatchType() string    { return u.RawType }

// Embed is a rich embed on an app's message.
type Embed struct {
	Title        string       `json:"title,omitempty"`
	URL          string       `json:"url,omitempty"`
	Description  string       `json:"description,omitempty"`
	Color        string       `json:"color,omitempty"`
	Fields       []EmbedField `json:"fields,omitempty"`
	ThumbnailURL string       `json:"thumbnail_url,omitempty"`
	ImageURL     string       `json:"image_url,omitempty"`
	Footer       *EmbedFooter `json:"footer,omitempty"`
}

// EmbedField is one name/value pair of an Embed.
type EmbedField struct {
	Name   string `json:"name"`
	Value  string `json:"value"`
	Inline bool   `json:"inline,omitempty"`
}

// EmbedFooter is an Embed's footer line.
type EmbedFooter struct {
	Text string `json:"text"`
}

// AppComponent is a button or select menu.
type AppComponent struct {
	// Type is "button" or "select".
	Type        string         `json:"type"`
	CustomID    string         `json:"custom_id"`
	Label       string         `json:"label,omitempty"`
	Style       string         `json:"style,omitempty"`
	Disabled    bool           `json:"disabled,omitempty"`
	Placeholder string         `json:"placeholder,omitempty"`
	MinValues   *int           `json:"min_values,omitempty"`
	MaxValues   *int           `json:"max_values,omitempty"`
	Options     []SelectOption `json:"options,omitempty"`
}

// SelectOption is one choice of a select AppComponent.
type SelectOption struct {
	Label       string `json:"label"`
	Value       string `json:"value"`
	Description string `json:"description,omitempty"`
}

// ComponentRow is a row of components; Type is always "row".
type ComponentRow struct {
	Type       string         `json:"type"`
	Components []AppComponent `json:"components"`
}

// Row builds a ComponentRow.
func Row(components ...AppComponent) ComponentRow {
	return ComponentRow{Type: "row", Components: components}
}

// GameLaunchCard is a "Play" card attached to a reply.
type GameLaunchCard struct {
	EntryURL     string `json:"entry_url"`
	Name         string `json:"name"`
	Description  string `json:"description,omitempty"`
	ThumbnailURL string `json:"thumbnail_url,omitempty"`
}

// Reply is the message an app posts in answer to a command.
type Reply struct {
	Body       string         `json:"body"`
	Embeds     []Embed        `json:"embeds,omitempty"`
	Components []ComponentRow `json:"components,omitempty"`
	ReplyTo    string         `json:"reply_to,omitempty"`
}

// Reaction is an emoji the app adds to a message.
type Reaction struct {
	MessageID string `json:"message_id"`
	Emoji     string `json:"emoji"`
}

// AppResponse is what a slash command handler answers.
type AppResponse struct {
	Reply *Reply `json:"reply,omitempty"`
	// Ephemeral shows the reply to the invoker only.
	Ephemeral bool       `json:"ephemeral,omitempty"`
	Reactions []Reaction `json:"reactions,omitempty"`
	// Defer says the app will post later on its own.
	Defer bool `json:"defer,omitempty"`
	// Game is attached to the reply; ignored without one.
	Game *GameLaunchCard `json:"game,omitempty"`
}

// ComponentUpdate replaces the interacted message's body or components.
type ComponentUpdate struct {
	Body       *string        `json:"body,omitempty"`
	Components []ComponentRow `json:"components,omitempty"`
}

// EphemeralReply is a reply only the interacting user sees.
type EphemeralReply struct {
	Body string `json:"body"`
}

// ComponentResponse is what a component interaction handler answers.
type ComponentResponse struct {
	Update         *ComponentUpdate `json:"update,omitempty"`
	EphemeralReply *EphemeralReply  `json:"ephemeral_reply,omitempty"`
	Defer          bool             `json:"defer,omitempty"`
}

// Signing bytes (wire-format.md, "Webhook delivery").

const (
	webhookDeliveryTag = "wavvon/webhook-delivery/v1\x00"
	webhookHKDFSalt    = "wavvon-webhook-signing"
)

// WebhookDeliverySigningBytes is "wavvon/webhook-delivery/v1\0" ||
// u64le(timestamp) || body.
func WebhookDeliverySigningBytes(timestamp uint64, body []byte) []byte {
	out := make([]byte, 0, len(webhookDeliveryTag)+8+len(body))
	out = append(out, webhookDeliveryTag...)
	out = binary.LittleEndian.AppendUint64(out, timestamp)
	return append(out, body...)
}

// DecodeWebhookSecret decodes an outgoing-webhook secret as the admin was
// shown it (base64url, no padding) into its raw bytes.
func DecodeWebhookSecret(shown string) ([]byte, error) {
	b, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(shown))
	if err != nil {
		return nil, errors.New("wavvon: webhook secret is not unpadded base64url")
	}
	return b, nil
}

// OutgoingWebhookSigningKey derives the HMAC key from the secret's raw bytes:
// HKDF-SHA256, salt "wavvon-webhook-signing", empty info, 32 bytes. The HMAC
// is keyed with these bytes, not their hex.
func OutgoingWebhookSigningKey(rawSecret []byte) []byte {
	key := make([]byte, 32)
	if _, err := io.ReadFull(hkdf.New(sha256.New, rawSecret, []byte(webhookHKDFSalt), nil), key); err != nil {
		panic(err) // unreachable: 32 bytes is far below HKDF's limit
	}
	return key
}

// VerifyOptions tune timestamp checking.
type VerifyOptions struct {
	// Now defaults to the clock.
	Now time.Time
	// Tolerance is the maximum |now - X-Wavvon-Timestamp|. Default 300 s.
	Tolerance time.Duration
}

func signedTimestamp(h http.Header, opts VerifyOptions) (uint64, []byte, error) {
	sigHex, tsText := h.Get("X-Wavvon-Signature-V1"), h.Get("X-Wavvon-Timestamp")
	// The body-only X-Wavvon-Signature is deliberately not accepted: on its
	// own a captured request replays forever.
	if sigHex == "" || tsText == "" {
		return 0, nil, &WebhookVerificationError{"missing X-Wavvon-Signature-V1 or X-Wavvon-Timestamp"}
	}
	ts, err := strconv.ParseUint(tsText, 10, 64)
	if err != nil {
		return 0, nil, &WebhookVerificationError{"malformed X-Wavvon-Timestamp"}
	}
	now := opts.Now
	if now.IsZero() {
		now = time.Now()
	}
	tol := opts.Tolerance
	if tol <= 0 {
		tol = 300 * time.Second
	}
	n := uint64(max(now.Unix(), 0))
	skew := max(ts, n) - min(ts, n)
	if skew > uint64(tol/time.Second) {
		return 0, nil, &WebhookVerificationError{"timestamp outside the allowed window"}
	}
	sig, err := hex.DecodeString(sigHex)
	if err != nil {
		return 0, nil, &WebhookVerificationError{"malformed signature"}
	}
	return ts, sig, nil
}

// VerifyDispatch verifies a slash command or component dispatch and decodes
// it. hubPublicKey is the hub's key as the program pinned it (GET /info
// public_key); the X-Wavvon-Hub-Pubkey header is only compared against it,
// never trusted. Pass the raw request bytes: re-serialised JSON will not verify.
func VerifyDispatch(h http.Header, body []byte, hubPublicKey string, opts VerifyOptions) (Dispatch, error) {
	if sent := h.Get("X-Wavvon-Hub-Pubkey"); sent != "" && !strings.EqualFold(sent, hubPublicKey) {
		return nil, &WebhookVerificationError{"signed by a different hub"}
	}
	ts, sig, err := signedTimestamp(h, opts)
	if err != nil {
		return nil, err
	}
	pub, err := hex.DecodeString(hubPublicKey)
	if err != nil || len(pub) != ed25519.PublicKeySize || !ed25519.Verify(pub, WebhookDeliverySigningBytes(ts, body), sig) {
		return nil, &WebhookVerificationError{"bad signature"}
	}
	rawType, err := objectType(body)
	if err != nil {
		return nil, err
	}
	var d Dispatch
	switch rawType {
	case "slash_command":
		d = new(SlashInvocation)
	case "component_interaction":
		d = new(ComponentInteraction)
	default:
		return &UnknownDispatch{RawType: rawType, Raw: append(json.RawMessage(nil), body...)}, nil
	}
	if err := json.Unmarshal(body, d); err != nil {
		return &UnknownDispatch{RawType: rawType, Raw: append(json.RawMessage(nil), body...)}, nil
	}
	return d, nil
}

func objectType(body []byte) (string, error) {
	var head map[string]json.RawMessage
	if err := json.Unmarshal(body, &head); err != nil || head == nil {
		return "", &WebhookVerificationError{"body is not a JSON object"}
	}
	var t string
	_ = json.Unmarshal(head["type"], &t)
	return t, nil
}

// OutgoingWebhookEvent is an outgoing-webhook delivery: a hub_event plus
// delivery fields.
type OutgoingWebhookEvent struct {
	Type string `json:"type"`
	HubEvent
	WebhookID string `json:"webhook_id,omitempty"`
	Truncated bool   `json:"truncated,omitempty"`
}

// VerifyOutgoingWebhook verifies an outgoing-webhook delivery (HMAC-SHA256)
// and decodes its envelope. secret is what the admin copied when the webhook
// was created or rotated (base64url, no padding).
func VerifyOutgoingWebhook(h http.Header, body []byte, secret string, opts VerifyOptions) (*OutgoingWebhookEvent, error) {
	raw, err := DecodeWebhookSecret(secret)
	if err != nil {
		return nil, &WebhookVerificationError{err.Error()}
	}
	ts, sig, err := signedTimestamp(h, opts)
	if err != nil {
		return nil, err
	}
	mac := hmac.New(sha256.New, OutgoingWebhookSigningKey(raw))
	mac.Write(WebhookDeliverySigningBytes(ts, body))
	if !hmac.Equal(sig, mac.Sum(nil)) {
		return nil, &WebhookVerificationError{"bad signature"}
	}
	if _, err := objectType(body); err != nil {
		return nil, err
	}
	ev := new(OutgoingWebhookEvent)
	if err := json.Unmarshal(body, ev); err != nil {
		return nil, &WebhookVerificationError{"body does not decode as a hub event: " + err.Error()}
	}
	return ev, nil
}

// DispatchHandler is an http.Handler for an app's webhook_url. It answers
// anything that does not verify with 401 and a verified dispatch with the
// handler's JSON. The hub waits 5 s for the answer. A nil handler answers {}.
type DispatchHandler struct {
	// HubPublicKey is the hub's key, hex, from GET /info.
	HubPublicKey   string
	OnSlashCommand func(context.Context, *SlashInvocation) (*AppResponse, error)
	OnComponent    func(context.Context, *ComponentInteraction) (*ComponentResponse, error)
	// OnUnknown handles a verified dispatch of a type this SDK does not know.
	OnUnknown func(context.Context, *UnknownDispatch) (any, error)
	Verify    VerifyOptions
}

const maxDispatchBody = 1 << 20

// ServeHTTP implements http.Handler.
func (d *DispatchHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxDispatchBody))
	if err != nil {
		http.Error(w, "body too large", http.StatusRequestEntityTooLarge)
		return
	}
	dispatch, err := VerifyDispatch(r.Header, body, d.HubPublicKey, d.Verify)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}
	var answer any
	switch v := dispatch.(type) {
	case *SlashInvocation:
		if d.OnSlashCommand != nil {
			answer, err = nilIfNil(d.OnSlashCommand(r.Context(), v))
		}
	case *ComponentInteraction:
		if d.OnComponent != nil {
			answer, err = nilIfNil(d.OnComponent(r.Context(), v))
		}
	case *UnknownDispatch:
		if d.OnUnknown != nil {
			answer, err = d.OnUnknown(r.Context(), v)
		}
	}
	if err != nil {
		http.Error(w, "handler failed", http.StatusInternalServerError)
		return
	}
	if answer == nil {
		answer = struct{}{}
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(answer)
}

// nilIfNil keeps a typed nil pointer from encoding as JSON null.
func nilIfNil[T any](v *T, err error) (any, error) {
	if v == nil {
		return nil, err
	}
	return v, err
}
