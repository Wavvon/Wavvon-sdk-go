package wavvon

// Asserts the tier-1 vectors from Wavvon-server's wire-vectors.json, the one
// authority for every signed byte sequence (sdk.md §4). The file is read,
// never copied in: point WAVVON_WIRE_VECTORS at a pinned copy, or keep the
// default sibling checkout.

import (
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

type vectorFile struct {
	Format   int                        `json:"format"`
	Fixtures map[string]string          `json:"fixtures"`
	Vectors  map[string]json.RawMessage `json:"vectors"`
}

// resolveRefs replaces every "@name" string with fixtures[name].
func resolveRefs(t *testing.T, v any, fixtures map[string]string) any {
	switch x := v.(type) {
	case string:
		if strings.HasPrefix(x, "@") {
			f, ok := fixtures[x[1:]]
			if !ok {
				t.Fatalf("unknown fixture %s", x)
			}
			return f
		}
	case []any:
		for i := range x {
			x[i] = resolveRefs(t, x[i], fixtures)
		}
	case map[string]any:
		for k := range x {
			x[k] = resolveRefs(t, x[k], fixtures)
		}
	}
	return v
}

type vector map[string]any

func (v vector) s(path ...string) string {
	var cur any = map[string]any(v)
	for _, p := range path {
		cur = cur.(map[string]any)[p]
	}
	switch x := cur.(type) {
	case string:
		return x
	case float64:
		return strconv.FormatFloat(x, 'f', -1, 64)
	}
	return ""
}

func unhex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex %q", s)
	}
	return b
}

func loadVectors(t *testing.T) func(string) vector {
	path := os.Getenv("WAVVON_WIRE_VECTORS")
	if path == "" {
		path = filepath.Join("..", "..", "server", "crates", "identity", "wire-vectors.json")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		bang := strings.Repeat("!", 72)
		msg := "\n" + bang + "\n!! CONFORMANCE VECTORS NOT FOUND at " + path + "\n!! The tier-1 wire vectors were NOT checked. Set WAVVON_WIRE_VECTORS.\n" + bang
		if os.Getenv("CI") != "" {
			t.Fatal(msg)
		}
		t.Skip(msg)
	}
	var f vectorFile
	if err := json.Unmarshal(data, &f); err != nil {
		t.Fatal(err)
	}
	if f.Format != 1 {
		t.Fatalf("wire-vectors format %d, this SDK speaks 1", f.Format)
	}
	return func(name string) vector {
		raw, ok := f.Vectors[name]
		if !ok {
			t.Fatalf("vector %s missing from %s", name, path)
		}
		var v map[string]any
		if err := json.Unmarshal(raw, &v); err != nil {
			t.Fatal(err)
		}
		return resolveRefs(t, v, f.Fixtures).(map[string]any)
	}
}

func TestConformance(t *testing.T) {
	vec := loadVectors(t)

	t.Run("auth_challenge", func(t *testing.T) {
		v := vec("auth_challenge")
		bytes, err := AuthChallengeSigningBytes(unhex(t, v.s("inputs", "challenge")), str("tagged-v1"))
		if err != nil || hex.EncodeToString(bytes) != v.s("signing_bytes") {
			t.Fatalf("signing bytes %x, %v", bytes, err)
		}
		id, _ := IdentityFromHexSeed(v.s("inputs", "signer_seed"))
		if hex.EncodeToString(id.Sign(bytes)) != v.s("signature") {
			t.Fatal("signature differs")
		}
	})

	t.Run("webhook_delivery_hub", func(t *testing.T) {
		v := vec("webhook_delivery_hub")
		ts, _ := strconv.ParseUint(v.s("inputs", "timestamp"), 10, 64)
		body := []byte(v.s("inputs", "body"))
		bytes := WebhookDeliverySigningBytes(ts, body)
		if hex.EncodeToString(bytes) != v.s("signing_bytes") {
			t.Fatalf("signing bytes %x", bytes)
		}
		hub, _ := IdentityFromHexSeed(v.s("inputs", "hub_seed"))
		if hub.PublicKey != v.s("hub_pubkey") {
			t.Fatal("hub pubkey differs")
		}
		if hex.EncodeToString(hub.Sign(bytes)) != v.s("signature_v1") {
			t.Fatal("signature differs")
		}
		h := http.Header{}
		h.Set(v.s("headers", "hub_pubkey"), v.s("hub_pubkey"))
		h.Set(v.s("headers", "signature_v1"), v.s("signature_v1"))
		h.Set(v.s("headers", "timestamp"), v.s("inputs", "timestamp"))
		d, err := VerifyDispatch(h, body, v.s("hub_pubkey"), VerifyOptions{Now: time.Unix(int64(ts), 0)})
		if err != nil || d.DispatchType() != "slash_command" {
			t.Fatalf("got %#v, %v", d, err)
		}
		if !ed25519.Verify(unhex(t, v.s("hub_pubkey")), bytes, unhex(t, v.s("signature_v1"))) {
			t.Fatal("stdlib verify disagrees")
		}
	})

	t.Run("webhook_delivery_outgoing", func(t *testing.T) {
		v := vec("webhook_delivery_outgoing")
		if v.s("inputs", "hkdf_salt") != webhookHKDFSalt || v.s("inputs", "hkdf_info") != "" {
			t.Fatal("HKDF parameters changed")
		}
		raw, err := DecodeWebhookSecret(v.s("inputs", "secret_as_shown"))
		if err != nil || hex.EncodeToString(raw) != v.s("inputs", "raw_secret") {
			t.Fatalf("decoded %x, %v", raw, err)
		}
		key := OutgoingWebhookSigningKey(raw)
		if hex.EncodeToString(key) != v.s("signing_key") {
			t.Fatalf("key %x", key)
		}
		ts, _ := strconv.ParseUint(v.s("inputs", "timestamp"), 10, 64)
		body := []byte(v.s("inputs", "body"))
		bytes := WebhookDeliverySigningBytes(ts, body)
		if hex.EncodeToString(bytes) != v.s("signing_bytes") {
			t.Fatalf("signing bytes %x", bytes)
		}
		mac := func(m []byte) string {
			h := hmac.New(sha256.New, key)
			h.Write(m)
			return hex.EncodeToString(h.Sum(nil))
		}
		if mac(bytes) != v.s("signature_v1") {
			t.Fatal("HMAC differs")
		}
		h := http.Header{}
		h.Set(v.s("headers", "signature_v1"), v.s("signature_v1"))
		h.Set(v.s("headers", "timestamp"), v.s("inputs", "timestamp"))
		h.Set(v.s("headers", "webhook_id"), "wh_test")
		ev, err := VerifyOutgoingWebhook(h, body, v.s("inputs", "secret_as_shown"), VerifyOptions{Now: time.Unix(int64(ts), 0)})
		if err != nil || ev.Type != "hub_event" {
			t.Fatalf("got %+v, %v", ev, err)
		}
	})
}
