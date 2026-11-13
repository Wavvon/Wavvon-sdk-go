package wavvon

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// AuthChallengeScheme is the challenge scheme older hubs name: the answer
// names no server.
const AuthChallengeScheme = "tagged-v1"

// BoundAuthChallengeScheme is the challenge scheme current hubs and farms
// name: the answer is bound to their public key.
const BoundAuthChallengeScheme = "tagged-v2"

const (
	authChallengeTag      = "wavvon/auth-challenge/v1\x00"
	boundAuthChallengeTag = "wavvon/auth-challenge/v2\x00"
	authChallengeLen      = 32
)

// Identity is a keypair the program holds. The private key never leaves it:
// only signatures do.
type Identity struct {
	// PublicKey is the Ed25519 public key, lowercase hex.
	PublicKey string
	key       ed25519.PrivateKey
}

// IdentityFromSeed builds an Identity from a 32-byte Ed25519 seed that the
// operator keeps in a file or environment variable.
func IdentityFromSeed(seed []byte) (*Identity, error) {
	if len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("wavvon: an Ed25519 seed is 32 bytes, got %d", len(seed))
	}
	key := ed25519.NewKeyFromSeed(seed)
	return &Identity{PublicKey: hex.EncodeToString(key.Public().(ed25519.PublicKey)), key: key}, nil
}

// IdentityFromHexSeed is IdentityFromSeed for a seed written as 64 hex characters.
func IdentityFromHexSeed(seed string) (*Identity, error) {
	b, err := hex.DecodeString(strings.TrimSpace(seed))
	if err != nil {
		return nil, fmt.Errorf("wavvon: seed is not hex: %w", err)
	}
	return IdentityFromSeed(b)
}

// Sign signs message with the identity's key.
func (id *Identity) Sign(message []byte) []byte { return ed25519.Sign(id.key, message) }

// AuthChallengeSigningBytes returns what a client signs to answer a challenge
// (wire-format.md, "Auth challenge answer"). Under "tagged-v2": the v2 tag,
// serverPubkey (u32 little-endian length, lowercase hex), then the challenge.
// serverPubkey must be the key the server's own GET /info presented, never one
// from the challenge response, or a hostile hub could relay another hub's
// challenge and sign in there. Under "tagged-v1" (older hubs): the v1 tag plus
// the challenge; serverPubkey is unused. scheme is nil when the hub's response
// has no scheme field. Any other scheme, a missing one included, and a
// challenge that is not 32 bytes are refused.
func AuthChallengeSigningBytes(challenge []byte, scheme *string, serverPubkey string) ([]byte, error) {
	if scheme == nil {
		return nil, &AuthSchemeError{"hub named no auth challenge scheme"}
	}
	if *scheme != AuthChallengeScheme && *scheme != BoundAuthChallengeScheme {
		return nil, &AuthSchemeError{fmt.Sprintf("unknown auth challenge scheme %q", *scheme)}
	}
	if len(challenge) != authChallengeLen {
		return nil, &AuthSchemeError{fmt.Sprintf("auth challenge is %d bytes, expected %d", len(challenge), authChallengeLen)}
	}
	if *scheme == AuthChallengeScheme {
		return append([]byte(authChallengeTag), challenge...), nil
	}
	if serverPubkey == "" {
		return nil, &AuthSchemeError{"tagged-v2 needs the server public key"}
	}
	b := []byte(boundAuthChallengeTag)
	b = binary.LittleEndian.AppendUint32(b, uint32(len(serverPubkey)))
	b = append(b, serverPubkey...)
	return append(b, challenge...), nil
}

// Session is a logged-in session on one hub.
type Session struct {
	Token string
	// Scope is "member", or "lobby" on a hub that holds newcomers back.
	Scope string
	// CanonicalPubkey is the identity the hub attributes this session's actions to.
	CanonicalPubkey string
}

// AuthOptions configure Authenticate.
type AuthOptions struct {
	// InviteCode admits the program on an invite_only hub. Ignored for members.
	InviteCode string
	Retry      RetryOptions
	// HTTPClient defaults to http.DefaultClient.
	HTTPClient *http.Client
}

// Authenticate runs challenge, sign, verify against hubURL. A transient
// failure at either step restarts from a fresh challenge, because the hub
// drops a pending challenge as soon as verify reads it.
func Authenticate(ctx context.Context, hubURL string, id *Identity, opts AuthOptions) (Session, error) {
	hc := opts.HTTPClient
	if hc == nil {
		hc = http.DefaultClient
	}
	base := strings.TrimRight(hubURL, "/")
	post := func(ctx context.Context, path string, body any) (*http.Response, error) {
		b, _ := json.Marshal(body)
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, base+path, bytes.NewReader(b))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", "application/json")
		return hc.Do(req)
	}

	var serverPubkey string
	res, err := DoWithRetry(ctx, opts.Retry, func(ctx context.Context) (*http.Response, error) {
		ch, err := post(ctx, "/auth/challenge", map[string]string{"public_key": id.PublicKey})
		if err != nil || ch.StatusCode != http.StatusOK {
			return ch, err
		}
		var c struct {
			Challenge string  `json:"challenge"`
			Scheme    *string `json:"scheme"`
		}
		err = json.NewDecoder(ch.Body).Decode(&c)
		ch.Body.Close()
		if err != nil {
			return nil, err
		}
		raw, err := hex.DecodeString(c.Challenge)
		if err != nil {
			return nil, &permanentError{&AuthSchemeError{"challenge is not hex"}}
		}
		if c.Scheme != nil && *c.Scheme == BoundAuthChallengeScheme && serverPubkey == "" {
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"/info", nil)
			if err != nil {
				return nil, err
			}
			info, err := hc.Do(req)
			if err != nil || info.StatusCode != http.StatusOK {
				return info, err
			}
			var i struct {
				PublicKey string `json:"public_key"`
			}
			err = json.NewDecoder(info.Body).Decode(&i)
			info.Body.Close()
			if err != nil {
				return nil, err
			}
			serverPubkey = i.PublicKey
		}
		msg, err := AuthChallengeSigningBytes(raw, c.Scheme, serverPubkey)
		if err != nil {
			return nil, &permanentError{err}
		}
		verify := map[string]string{
			"public_key": id.PublicKey,
			"challenge":  c.Challenge,
			"signature":  hex.EncodeToString(id.Sign(msg)),
		}
		if opts.InviteCode != "" {
			verify["invite_code"] = opts.InviteCode
		}
		return post(ctx, "/auth/verify", verify)
	})
	if err != nil {
		return Session{}, err
	}
	defer res.Body.Close()
	body, _ := io.ReadAll(res.Body)
	if res.StatusCode != http.StatusOK {
		return Session{}, &HubError{Status: res.StatusCode, Body: string(body)}
	}
	var s struct {
		Token           string `json:"token"`
		Scope           string `json:"scope"`
		CanonicalPubkey string `json:"canonical_pubkey"`
	}
	if err := json.Unmarshal(body, &s); err != nil || s.Token == "" {
		return Session{}, &HubError{Status: res.StatusCode, Body: "verify answered without a token: " + string(body)}
	}
	if s.Scope == "" {
		s.Scope = "member"
	}
	if s.CanonicalPubkey == "" {
		s.CanonicalPubkey = id.PublicKey
	}
	return Session{Token: s.Token, Scope: s.Scope, CanonicalPubkey: s.CanonicalPubkey}, nil
}
