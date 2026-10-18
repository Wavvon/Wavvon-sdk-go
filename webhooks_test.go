package wavvon

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

var (
	hubKey = ed25519.NewKeyFromSeed(bytes.Repeat([]byte{5}, 32))
	hubPub = hex.EncodeToString(hubKey.Public().(ed25519.PublicKey))
	now    = time.Unix(1_700_000_000, 0)
)

func signedDispatch(body string, ts int64) http.Header {
	h := http.Header{}
	h.Set("X-Wavvon-Hub-Pubkey", hubPub)
	h.Set("X-Wavvon-Signature-V1", hex.EncodeToString(ed25519.Sign(hubKey, WebhookDeliverySigningBytes(uint64(ts), []byte(body)))))
	h.Set("X-Wavvon-Timestamp", strconv.FormatInt(ts, 10))
	return h
}

const slash = `{"type":"slash_command","hub_url":"https://h","channel_id":"c","message_id_hint":"m","author":{"pubkey":"p"},"command":"echo","args_raw":"hi there","args_tokens":["hi","there"]}`

func rejected(err error) bool {
	var we *WebhookVerificationError
	return errors.As(err, &we)
}

func TestVerifyDispatchAcceptsAndDecodes(t *testing.T) {
	d, err := VerifyDispatch(signedDispatch(slash, now.Unix()), []byte(slash), hubPub, VerifyOptions{Now: now})
	inv, ok := d.(*SlashInvocation)
	if err != nil || !ok || inv.Command != "echo" || inv.ArgsRaw != "hi there" {
		t.Fatalf("got %#v, %v", d, err)
	}
}

func TestVerifyDispatchRefusesTamperingStalenessLegacyOnlyAndForeignHubs(t *testing.T) {
	h := signedDispatch(slash, now.Unix())
	if _, err := VerifyDispatch(h, []byte(strings.Replace(slash, "echo", "ban", 1)), hubPub, VerifyOptions{Now: now}); !rejected(err) {
		t.Errorf("tampered body: %v", err)
	}
	if _, err := VerifyDispatch(h, []byte(slash), hubPub, VerifyOptions{Now: now.Add(301 * time.Second)}); !rejected(err) {
		t.Errorf("stale: %v", err)
	}
	if _, err := VerifyDispatch(h, []byte(slash), hubPub, VerifyOptions{Now: now.Add(300 * time.Second)}); err != nil {
		t.Errorf("edge of window: %v", err)
	}
	legacy := h.Clone()
	legacy.Del("X-Wavvon-Signature-V1")
	if _, err := VerifyDispatch(legacy, []byte(slash), hubPub, VerifyOptions{Now: now}); !rejected(err) {
		t.Errorf("legacy only: %v", err)
	}
	other := hex.EncodeToString(ed25519.NewKeyFromSeed(bytes.Repeat([]byte{6}, 32)).Public().(ed25519.PublicKey))
	if _, err := VerifyDispatch(h, []byte(slash), other, VerifyOptions{Now: now}); !rejected(err) {
		t.Errorf("foreign hub: %v", err)
	}
}

func TestVerifyDispatchDeliversAnUnknownType(t *testing.T) {
	body := `{"type":"modal_submit","x":1}`
	d, err := VerifyDispatch(signedDispatch(body, now.Unix()), []byte(body), hubPub, VerifyOptions{Now: now})
	u, ok := d.(*UnknownDispatch)
	if err != nil || !ok || u.RawType != "modal_submit" || string(u.Raw) != body {
		t.Fatalf("got %#v, %v", d, err)
	}
}

func TestDispatchHandler(t *testing.T) {
	handler := &DispatchHandler{
		HubPublicKey: hubPub,
		Verify:       VerifyOptions{Now: now},
		OnSlashCommand: func(_ context.Context, inv *SlashInvocation) (*AppResponse, error) {
			return &AppResponse{Reply: &Reply{Body: inv.ArgsRaw}, Ephemeral: true}, nil
		},
	}
	req := httptest.NewRequest(http.MethodPost, "/hook", strings.NewReader(slash))
	req.Header = signedDispatch(slash, now.Unix())
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	var got map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &got)
	if rec.Code != 200 || got["ephemeral"] != true || got["reply"].(map[string]any)["body"] != "hi there" {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}

	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/hook", strings.NewReader(slash)))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("unsigned request answered %d", rec.Code)
	}
}

func TestVerifyOutgoingWebhook(t *testing.T) {
	secret := "BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc"
	raw, err := DecodeWebhookSecret(secret)
	if err != nil || !bytes.Equal(raw, bytes.Repeat([]byte{7}, 32)) {
		t.Fatalf("decoded %x, %v", raw, err)
	}
	body := []byte(`{"type":"hub_event","seq":3,"event":"member.joined","hub_url":"h","at":1700000000,"payload":{}}`)
	mac := hmac.New(sha256.New, OutgoingWebhookSigningKey(raw))
	mac.Write(WebhookDeliverySigningBytes(uint64(now.Unix()), body))
	h := http.Header{}
	h.Set("x-wavvon-signature-v1", hex.EncodeToString(mac.Sum(nil)))
	h.Set("x-wavvon-timestamp", strconv.FormatInt(now.Unix(), 10))

	ev, err := VerifyOutgoingWebhook(h, body, secret, VerifyOptions{Now: now})
	if err != nil || ev.Seq != 3 || ev.Event != "member.joined" {
		t.Fatalf("got %+v, %v", ev, err)
	}
	if _, err := VerifyOutgoingWebhook(h, body, "AAAA", VerifyOptions{Now: now}); !rejected(err) {
		t.Errorf("wrong secret: %v", err)
	}
	if _, err := VerifyOutgoingWebhook(h, body, secret, VerifyOptions{Now: now.Add(-400 * time.Second)}); !rejected(err) {
		t.Errorf("replay outside the window: %v", err)
	}
}
