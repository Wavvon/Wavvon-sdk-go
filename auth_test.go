package wavvon

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

var seedHex = strings.Repeat("5a", 32)

func str(s string) *string { return &s }

func TestTaggedV1PrefixesTheTag(t *testing.T) {
	c := bytes.Repeat([]byte{9}, 32)
	b, err := AuthChallengeSigningBytes(c, str("tagged-v1"))
	if err != nil || string(b[:25]) != "wavvon/auth-challenge/v1\x00" || !bytes.Equal(b[25:], c) {
		t.Fatalf("got %x, %v", b, err)
	}
}

func TestUnknownOrMissingSchemeIsRefused(t *testing.T) {
	for _, s := range []*string{nil, str(""), str("tagged-v2")} {
		var se *AuthSchemeError
		if _, err := AuthChallengeSigningBytes(make([]byte, 32), s); !errors.As(err, &se) {
			t.Errorf("scheme %v: want AuthSchemeError, got %v", s, err)
		}
	}
}

func TestSeedAsHexOrBytes(t *testing.T) {
	a, err := IdentityFromHexSeed(seedHex)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := hex.DecodeString(seedHex)
	b, _ := IdentityFromSeed(raw)
	if a.PublicKey != b.PublicKey {
		t.Fatal("hex and bytes seeds differ")
	}
	if _, err := IdentityFromHexSeed("abcd"); err == nil {
		t.Fatal("short seed accepted")
	}
}

// authHub answers the challenge flow. failVerify transient verifies first;
// verifyStatus refuses every verify with that status.
type authHub struct {
	mu           sync.Mutex
	scheme       *string
	failVerify   int
	verifyStatus int
	challenges   []string
	verifies     []map[string]string
	bodies       []string
}

func (h *authHub) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.mu.Lock()
	defer h.mu.Unlock()
	raw := new(bytes.Buffer)
	_, _ = raw.ReadFrom(r.Body)
	h.bodies = append(h.bodies, raw.String())
	var body map[string]string
	_ = json.Unmarshal(raw.Bytes(), &body)
	switch r.URL.Path {
	case "/auth/challenge":
		ch := hex.EncodeToString(bytes.Repeat([]byte{byte(len(h.challenges) + 1)}, 32))
		h.challenges = append(h.challenges, ch)
		resp := map[string]any{"challenge": ch}
		if h.scheme != nil {
			resp["scheme"] = *h.scheme
		}
		_ = json.NewEncoder(w).Encode(resp)
	case "/auth/verify":
		h.verifies = append(h.verifies, body)
		if h.failVerify > 0 {
			h.failVerify--
			http.Error(w, "busy", http.StatusServiceUnavailable)
			return
		}
		if h.verifyStatus != 0 {
			http.Error(w, "This hub requires an invite code", h.verifyStatus)
			return
		}
		ch, _ := hex.DecodeString(body["challenge"])
		msg, _ := AuthChallengeSigningBytes(ch, h.scheme)
		sig, _ := hex.DecodeString(body["signature"])
		pub, _ := hex.DecodeString(body["public_key"])
		if len(pub) != ed25519.PublicKeySize || !ed25519.Verify(pub, msg, sig) {
			http.Error(w, "Invalid signature", http.StatusUnauthorized)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"token": "tok", "scope": "member", "canonical_pubkey": body["public_key"]})
	}
}

var fast = RetryOptions{BaseDelay: time.Millisecond, MaxDelay: time.Millisecond}

func identity(t *testing.T) *Identity {
	t.Helper()
	id, err := IdentityFromHexSeed(seedHex)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func TestLoginWithTaggedV1PassesTheInvite(t *testing.T) {
	h := &authHub{scheme: str("tagged-v1")}
	srv := httptest.NewServer(h)
	defer srv.Close()
	s, err := Authenticate(context.Background(), srv.URL+"/", identity(t), AuthOptions{InviteCode: "inv"})
	if err != nil || s.Token != "tok" || h.verifies[0]["invite_code"] != "inv" {
		t.Fatalf("got %+v, %v", s, err)
	}
}

func TestTransientVerifyFailureRestartsFromAFreshChallenge(t *testing.T) {
	h := &authHub{scheme: str("tagged-v1"), failVerify: 2}
	srv := httptest.NewServer(h)
	defer srv.Close()
	if _, err := Authenticate(context.Background(), srv.URL, identity(t), AuthOptions{Retry: fast}); err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, v := range h.verifies {
		seen[v["challenge"]] = true
	}
	if len(h.challenges) != 3 || len(seen) != 3 {
		t.Fatalf("%d challenges, %d distinct verified", len(h.challenges), len(seen))
	}
}

func TestDefinitiveRefusalIsHubError(t *testing.T) {
	srv := httptest.NewServer(&authHub{scheme: str("tagged-v1"), verifyStatus: 403})
	defer srv.Close()
	_, err := Authenticate(context.Background(), srv.URL, identity(t), AuthOptions{})
	var he *HubError
	if !errors.As(err, &he) || he.Status != 403 {
		t.Fatalf("got %v", err)
	}
}

func TestUnknownSchemeFailsLoginWithoutRetrying(t *testing.T) {
	h := &authHub{scheme: str("tagged-v9")}
	srv := httptest.NewServer(h)
	defer srv.Close()
	_, err := Authenticate(context.Background(), srv.URL, identity(t), AuthOptions{Retry: fast})
	var se *AuthSchemeError
	if !errors.As(err, &se) || len(h.challenges) != 1 {
		t.Fatalf("got %v after %d challenges", err, len(h.challenges))
	}
}

func TestNeverSendsTheSeed(t *testing.T) {
	h := &authHub{scheme: str("tagged-v1")}
	srv := httptest.NewServer(h)
	defer srv.Close()
	if _, err := Authenticate(context.Background(), srv.URL, identity(t), AuthOptions{InviteCode: "x"}); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(strings.Join(h.bodies, ""), seedHex) {
		t.Fatal("seed left the process")
	}
}
