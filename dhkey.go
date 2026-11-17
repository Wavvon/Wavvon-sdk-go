package wavvon

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
)

// The program's X25519 key and its peers': publish, look up, verify, pin. One
// key serves DMs and voice (sdk-voice.md section 2, sdk-dm.md section 1).

func (id *Identity) dhSecret() key32 { return dhSecretFromSeed(id.key.Seed()) }

// DHPublicKeyHex is the X25519 public key peers wrap voice keys and DMs to:
// SHA-512 of the seed, clamped (vector master_dh_pubkey).
func (id *Identity) DHPublicKeyHex() string {
	pub := x25519Pub(id.dhSecret())
	return hex.EncodeToString(pub[:])
}

// jsonCall sends one authenticated request (bearer, retry and re-login on 401
// as for every call) and decodes a 2xx answer into out. A 4xx other than 429
// is *HubError; an exhausted retry budget is *HubUnavailableError.
func (c *Client) jsonCall(ctx context.Context, method, path string, query url.Values, body, out any) error {
	var rdr io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rdr = bytes.NewReader(b)
	}
	u := c.HubURL + path
	if len(query) > 0 {
		u += "?" + query.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, method, u, rdr)
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	res, err := c.do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	data, err := io.ReadAll(res.Body)
	if err != nil {
		return err
	}
	if res.StatusCode < 200 || res.StatusCode > 299 {
		return &HubError{Status: res.StatusCode, Body: string(data)}
	}
	if out == nil {
		return nil
	}
	if err := json.Unmarshal(data, out); err != nil {
		return fmt.Errorf("wavvon: %s %s: unexpected response: %w", method, path, err)
	}
	return nil
}

func isNotFound(err error) bool {
	he, ok := err.(*HubError)
	return ok && he.Status == http.StatusNotFound
}

// PublishDHKey publishes this program's DH key on this hub, once per hub.
// Without it nobody can wrap a voice key or encrypt a DM to the program, and
// the program cannot unwrap theirs. It reports false when the hub already held
// exactly this key.
func (c *Client) PublishDHKey(ctx context.Context) (bool, error) {
	if _, err := c.Login(ctx); err != nil {
		return false, err
	}
	own := c.Identity.PublicKey
	dh := c.Identity.DHPublicKeyHex()
	published, err := c.fetchDHRecord(ctx, own)
	if err == nil && published == dh {
		return false, nil
	}
	if _, unsigned := err.(*DHKeyUnsignedError); err != nil && !unsigned {
		return false, err
	}
	sig := hex.EncodeToString(c.Identity.Sign(DHKeyRecordSigningBytes(own, dh)))
	err = c.jsonCall(ctx, http.MethodPut, "/identity/"+url.PathEscape(own)+"/dh-key", nil,
		map[string]string{"dh_pubkey_hex": dh, "signature_hex": sig}, nil)
	return err == nil, err
}

// fetchDHRecord returns "" when the hub has no key for pubkey. A record
// pubkey did not sign is *DHKeyUnsignedError, never "no key".
func (c *Client) fetchDHRecord(ctx context.Context, pubkey string) (string, error) {
	var rec struct {
		DHPubkeyHex  string `json:"dh_pubkey_hex"`
		SignatureHex string `json:"signature_hex"`
	}
	err := c.jsonCall(ctx, http.MethodGet, "/identity/"+url.PathEscape(pubkey)+"/dh-key", nil, nil, &rec)
	if isNotFound(err) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	if rec.DHPubkeyHex == "" {
		return "", nil
	}
	sig, derr := hex.DecodeString(rec.SignatureHex)
	if derr != nil || verifySig(pubkey, DHKeyRecordSigningBytes(pubkey, rec.DHPubkeyHex), sig) != nil {
		return "", &DHKeyUnsignedError{PublicKey: pubkey}
	}
	return rec.DHPubkeyHex, nil
}

func pinKey(pubkey string) string { return "dh-pin/" + pubkey }

func hex32(s string) (key32, bool) {
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != 32 {
		return key32{}, false
	}
	return key32(b), true
}

// PeerDHKey is a peer's verified, pinned DH key. The first key seen is
// pinned; a different validly signed one is *DHKeyChangedError and is not
// used. A 404 is *RecipientHasNoKeyError; 429, 5xx and timeouts are retried
// and surface as *HubUnavailableError, never as either.
func (c *Client) PeerDHKey(ctx context.Context, pubkey string) ([32]byte, error) {
	dh, err := c.fetchDHRecord(ctx, pubkey)
	if err != nil {
		return key32{}, err
	}
	if dh == "" {
		return key32{}, &RecipientHasNoKeyError{PublicKey: pubkey}
	}
	raw, ok := hex32(dh)
	if !ok {
		return key32{}, fmt.Errorf("wavvon: DH key of %s is not 32 bytes of hex", pubkey)
	}
	pinned, err := c.store.Get(pinKey(pubkey))
	if err != nil {
		return key32{}, err
	}
	switch {
	case pinned == nil:
		if err := c.store.Put(pinKey(pubkey), []byte(dh)); err != nil {
			return key32{}, err
		}
	case string(pinned) != dh:
		return key32{}, &DHKeyChangedError{PublicKey: pubkey, Pinned: string(pinned), Fetched: dh}
	}
	return raw, nil
}

// AcceptDHKey re-pins what the hub now holds for pubkey, after the program
// checked out a changed key. When to call it is the program's policy.
func (c *Client) AcceptDHKey(ctx context.Context, pubkey string) error {
	dh, err := c.fetchDHRecord(ctx, pubkey)
	if err != nil {
		return err
	}
	if dh == "" {
		return &RecipientHasNoKeyError{PublicKey: pubkey}
	}
	return c.store.Put(pinKey(pubkey), []byte(dh))
}
