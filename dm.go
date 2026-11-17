package wavvon

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"sync"
	"time"
)

// End-to-end encrypted DMs for a program (sdk-dm.md): 1:1 double ratchet (v2
// send, v2 and v1 receive) and group sender keys. Nothing here ever falls
// back to plaintext: that is the separate, explicit SendPlaintext.

const (
	maxSkip    = 1000
	plainCache = 2048
	seenCap    = 4096
)

// DMPlaintext is what a DM carries inside its ciphertext.
type DMPlaintext struct {
	Content string `json:"content"`
	// Attachments are descriptors as the clients write them. Omitted when empty.
	Attachments []any `json:"attachments,omitempty"`
}

// Conversation is a DM conversation.
type Conversation struct {
	ID string `json:"id"`
	// ConvType is "dm" for 1:1, "group" otherwise.
	ConvType string   `json:"conv_type"`
	Members  []string `json:"members"`
}

// DMMessage is one message of a conversation as read. Err is per message: a
// program keeps going past one it cannot read. A row the hub stored in the
// clear has Encrypted false; what to do about that is the program's call.
type DMMessage struct {
	ID             string
	ConversationID string
	Sender         string
	SenderName     *string
	CreatedAt      int64
	Encrypted      bool
	// Content is valid when Err is nil.
	Content DMPlaintext
	// Err says why the message could not be read: a *DMError, a pin or
	// missing-key error for the sender.
	Err error
}

// SkippedMember is a group member who was not given a sender key.
type SkippedMember struct {
	PublicKey string
	// Err is *RecipientHasNoKeyError, *DHKeyChangedError or *DHKeyUnsignedError.
	Err error
}

// Distribution says who got a group sender key and who was skipped (no DH
// key, a changed key). A skipped member cannot read messages under that key.
type Distribution struct {
	Version   uint32
	Delivered []string
	Skipped   []SkippedMember
}

// Sent is a message the hub accepted.
type Sent struct {
	ID        string
	CreatedAt int64
	// Distribution is set when this send created the group sender key first.
	Distribution *Distribution
}

// MessagesPage selects a page of Messages.
type MessagesPage struct {
	// Limit is 1..100; 0 is the hub's default.
	Limit int
	// Cursor pages backwards: the id of the oldest message already held.
	Cursor string
}

type dmShared struct {
	mu sync.Mutex // one ratchet is never advanced by two goroutines at once

	cacheMu sync.Mutex
	plain   map[string]DMPlaintext
	order   []string

	seen      map[string]struct{}
	seenOrder []string
}

// Dms is a program's DMs. Obtain it with Client.DMs.
type Dms struct {
	c *Client
	s dmShared
}

// DMs returns the client's E2E DMs. Publish the DH key first (PublishDHKey).
// Every call returns the same value: its sessions and caches are shared.
func (c *Client) DMs() *Dms {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.dms == nil {
		c.dms = &Dms{c: c, s: dmShared{plain: map[string]DMPlaintext{}, seen: map[string]struct{}{}}}
	}
	return c.dms
}

func (d *Dms) me() string { return d.c.Identity.PublicKey }

// ---------------------------------------------------------------------------
// State, persisted as JSON (the ratchet's shape matches the desktop client's)
// ---------------------------------------------------------------------------

type drSession struct {
	RK        string            `json:"rk"`
	CKS       *string           `json:"cks"`
	CKR       *string           `json:"ckr"`
	NS        uint32            `json:"ns"`
	NR        uint32            `json:"nr"`
	PN        uint32            `json:"pn"`
	DHSPriv   string            `json:"dhs_priv"`
	DHSPub    string            `json:"dhs_pub"`
	DHR       *string           `json:"dhr"`
	MKSkipped map[string]string `json:"mkskipped"`
}

func hexp(k key32) *string { s := hex.EncodeToString(k[:]); return &s }

func h32(s string) (key32, error) {
	k, ok := hex32(s)
	if !ok {
		return key32{}, dmErr(ErrDMMalformed, "expected 32 bytes of hex")
	}
	return k, nil
}

func cryptoErr(err error) error { return dmErr(ErrDMMalformed, err.Error()) }

func newDRInitiator(myStatic, theirStatic key32, conv string, eph key32) (*drSession, error) {
	in, err := drInitiatorInit(myStatic, theirStatic, conv, eph)
	if err != nil {
		return nil, cryptoErr(err)
	}
	return &drSession{
		RK: hex.EncodeToString(in.rk[:]), CKS: hexp(in.cks),
		DHSPriv: hex.EncodeToString(eph[:]), DHSPub: hex.EncodeToString(in.ephPub[:]),
		MKSkipped: map[string]string{},
	}, nil
}

func newDRResponder(myStatic, theirStatic key32, conv, incomingDHR string, eph key32) (*drSession, error) {
	inc, err := h32(incomingDHR)
	if err != nil {
		return nil, err
	}
	in, err := drResponderInit(myStatic, theirStatic, conv, inc, eph)
	if err != nil {
		return nil, cryptoErr(err)
	}
	dhr := incomingDHR
	return &drSession{
		RK: hex.EncodeToString(in.rk[:]), CKS: hexp(in.cks), CKR: hexp(in.ckr),
		DHSPriv: hex.EncodeToString(eph[:]), DHSPub: hex.EncodeToString(in.ephPub[:]),
		DHR: &dhr, MKSkipped: map[string]string{},
	}, nil
}

// seal seals plaintext, advancing the sending chain; it returns the
// ciphertext, message_index and prev_count.
func (s *drSession) seal(plaintext []byte) ([]byte, uint32, uint32, error) {
	if s.CKS == nil {
		return nil, 0, 0, dmErr(ErrDMNoSession, "")
	}
	cks, err := h32(*s.CKS)
	if err != nil {
		return nil, 0, 0, err
	}
	mk, next := drKDFCK(cks)
	ct := drMessageSeal(mk, plaintext)
	index, prev := s.NS, s.PN
	s.CKS = hexp(next)
	s.NS++
	return ct, index, prev, nil
}

// open is the receive algorithm of e2e-encryption.md "1:1 DM Encryption - v2":
// skipped-key cache, DH-ratchet step on a new remote key, chain advance. The
// caller works on a copy and keeps it only on success.
func (s *drSession) open(dhPub string, index, prev uint32, ct []byte) ([]byte, error) {
	opened := func(mk key32) ([]byte, error) {
		out, err := drMessageOpen(mk, ct)
		if err != nil {
			return nil, dmErr(ErrDMDecryptionFailed, "")
		}
		return out, nil
	}
	if mkHex, ok := s.MKSkipped[dhPub+":"+strconv.FormatUint(uint64(index), 10)]; ok {
		delete(s.MKSkipped, dhPub+":"+strconv.FormatUint(uint64(index), 10))
		mk, err := h32(mkHex)
		if err != nil {
			return nil, err
		}
		return opened(mk)
	}
	if s.DHR == nil || *s.DHR != dhPub {
		if s.CKR != nil {
			old := ""
			if s.DHR != nil {
				old = *s.DHR
			}
			ckr, err := h32(*s.CKR)
			if err != nil {
				return nil, err
			}
			if _, err := s.skip(old, ckr, s.NR, prev); err != nil {
				return nil, err
			}
		}
		their, err := h32(dhPub)
		if err != nil {
			return nil, err
		}
		rk, err := h32(s.RK)
		if err != nil {
			return nil, err
		}
		mySecret, err := h32(s.DHSPriv)
		if err != nil {
			return nil, err
		}
		d1, err := x25519(mySecret, their)
		if err != nil {
			return nil, cryptoErr(err)
		}
		rk, ckr := drKDFRK(rk, d1)
		newPriv := randomKey()
		d2, err := x25519(newPriv, their)
		if err != nil {
			return nil, cryptoErr(err)
		}
		rk, cks := drKDFRK(rk, d2)
		pub := x25519Pub(newPriv)
		s.RK = hex.EncodeToString(rk[:])
		s.CKS = hexp(cks)
		s.PN = s.NS
		s.NS = 0
		s.NR = 0
		d := dhPub
		s.DHR = &d
		s.CKR = hexp(ckr)
		s.DHSPriv = hex.EncodeToString(newPriv[:])
		s.DHSPub = hex.EncodeToString(pub[:])
	}
	if s.CKR == nil {
		return nil, dmErr(ErrDMNoSession, "")
	}
	ckr, err := h32(*s.CKR)
	if err != nil {
		return nil, err
	}
	ckr, err = s.skip(dhPub, ckr, s.NR, index)
	if err != nil {
		return nil, err
	}
	mk, next := drKDFCK(ckr)
	plain, err := opened(mk)
	if err != nil {
		return nil, err
	}
	s.CKR = hexp(next)
	s.NR = index + 1
	return plain, nil
}

// skip caches the message keys of chain dh from `from` up to (not including)
// `to` and returns the chain key at `to`.
func (s *drSession) skip(dh string, ck key32, from, to uint32) (key32, error) {
	var gap int
	if to > from {
		gap = int(to - from)
	}
	if len(s.MKSkipped)+gap > maxSkip {
		return key32{}, dmErr(ErrDMTooManySkipped, "")
	}
	if s.MKSkipped == nil {
		s.MKSkipped = map[string]string{}
	}
	for n := from; n < to; n++ {
		mk, next := drKDFCK(ck)
		s.MKSkipped[dh+":"+strconv.FormatUint(uint64(n), 10)] = hex.EncodeToString(mk[:])
		ck = next
	}
	return ck, nil
}

type groupOwn struct {
	Version   uint32 `json:"version"`
	ChainKey  string `json:"chain_key"`
	Iteration uint32 `json:"iteration"`
}

type groupPeer struct {
	ChainKey  string `json:"chain_key"`
	Iteration uint32 `json:"iteration"`
}

func getJSON[T any](s StateStore, key string) (*T, error) {
	b, err := s.Get(key)
	if err != nil || b == nil {
		return nil, err
	}
	v := new(T)
	if err := json.Unmarshal(b, v); err != nil {
		return nil, fmt.Errorf("wavvon: state %s is not valid: %w", key, err)
	}
	return v, nil
}

func putJSON(s StateStore, key string, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return s.Put(key, b)
}

// ---------------------------------------------------------------------------
// Envelope checks
// ---------------------------------------------------------------------------

type envelope map[string]any

func (e envelope) text(k string) string { s, _ := e[k].(string); return s }

func (e envelope) u32(k string) (uint32, bool) {
	f, ok := e[k].(float64)
	if !ok || f < 0 || f > 1<<32-1 || f != float64(uint32(f)) {
		return 0, false
	}
	return uint32(f), true
}

// verifyEnvelope checks that sender (the member the hub names) signed the
// envelope: directly, or through a device whose SubkeyCert sender issued. The
// hub checked too; a program does not rely on that.
func verifyEnvelope(conv string, env envelope, sender string) error {
	bad := dmErr(ErrDMNotSignedBySender, "")
	if env.text("sender_pubkey") != sender {
		return bad
	}
	var signed []byte
	if _, ok := env["sender_key_version"]; ok {
		version, ok1 := env.u32("sender_key_version")
		iteration, ok2 := env.u32("iteration")
		if !ok1 || !ok2 {
			return bad
		}
		signed = GroupDMEnvelopeSigningBytes(conv, version, iteration, env.text("ciphertext_hex"), env.text("nonce_hex"))
	} else if v, _ := env["v"].(float64); v == 2 {
		index, ok1 := env.u32("message_index")
		prev, ok2 := env.u32("prev_count")
		if !ok1 || !ok2 {
			return bad
		}
		signed = DREnvelopeSigningBytes(conv, index, prev, env.text("ciphertext_hex"), env.text("dh_pubkey_hex"))
	} else {
		signed = DMEnvelopeSigningBytes(conv, env.text("ciphertext_hex"), env.text("nonce_hex"), env.text("dh_pubkey_hex"))
	}
	sig, err := hex.DecodeString(env.text("signature_hex"))
	if err != nil {
		return bad
	}
	signer := sender
	if raw, ok := env["signer_cert"]; ok && raw != nil {
		b, _ := json.Marshal(raw)
		var cert SubkeyCert
		if json.Unmarshal(b, &cert) != nil || cert.MasterPubkey != sender || cert.Verify() != nil {
			return bad
		}
		signer = cert.SubkeyPubkey
	}
	if verifySig(signer, signed, sig) != nil {
		return bad
	}
	return nil
}

func parsePlaintext(b []byte) (DMPlaintext, error) {
	var p DMPlaintext
	if err := json.Unmarshal(b, &p); err != nil {
		return p, dmErr(ErrDMMalformed, "plaintext JSON: "+err.Error())
	}
	return p, nil
}

func (e envelope) hexField(k string) ([]byte, error) {
	b, err := hex.DecodeString(e.text(k))
	if err != nil {
		return nil, dmErr(ErrDMMalformed, k+" is not hex")
	}
	return b, nil
}

func (e envelope) mustU32(k string) (uint32, error) {
	v, ok := e.u32(k)
	if !ok {
		return 0, dmErr(ErrDMMalformed, k+" missing")
	}
	return v, nil
}

// ---------------------------------------------------------------------------
// Conversations and sending
// ---------------------------------------------------------------------------

// Conversation fetches one conversation.
func (d *Dms) Conversation(ctx context.Context, id string) (*Conversation, error) {
	var conv Conversation
	if err := d.c.jsonCall(ctx, http.MethodGet, "/conversations/"+url.PathEscape(id), nil, nil, &conv); err != nil {
		return nil, err
	}
	return &conv, nil
}

// Conversations lists every conversation, paged to exhaustion where the hub
// pages (capability list.cursor.lists).
func (d *Dms) Conversations(ctx context.Context) ([]Conversation, error) {
	paged, err := d.c.HasCapability(ctx, "list.cursor.lists")
	if err != nil {
		return nil, err
	}
	var out []Conversation
	for {
		q := url.Values{}
		if paged {
			q.Set("limit", "500")
			if len(out) > 0 {
				q.Set("cursor", out[len(out)-1].ID)
			}
		}
		var page []Conversation
		if err := d.c.jsonCall(ctx, http.MethodGet, "/conversations", q, nil, &page); err != nil {
			return nil, err
		}
		out = append(out, page...)
		if !paged || len(page) < 500 {
			return out, nil
		}
	}
}

// CreateConversation creates a conversation with members (the others; the hub
// adds the caller). A 1:1 with a member you already talk to is returned, not
// duplicated.
func (d *Dms) CreateConversation(ctx context.Context, members []string) (*Conversation, error) {
	var conv Conversation
	if err := d.c.jsonCall(ctx, http.MethodPost, "/conversations", nil, map[string]any{"members": members}, &conv); err != nil {
		return nil, err
	}
	return &conv, nil
}

// SendText is Send with a text-only message.
func (d *Dms) SendText(ctx context.Context, conv, text string) (*Sent, error) {
	return d.Send(ctx, conv, DMPlaintext{Content: text})
}

// Send encrypts and sends: the double ratchet in a 1:1, the sender-key chain
// in a group. It fails with *RecipientHasNoKeyError or *DHKeyChangedError
// rather than ever sending in the clear.
func (d *Dms) Send(ctx context.Context, conv string, message DMPlaintext) (*Sent, error) {
	d.s.mu.Lock()
	defer d.s.mu.Unlock()
	c, err := d.Conversation(ctx, conv)
	if err != nil {
		return nil, err
	}
	plaintext, err := json.Marshal(message)
	if err != nil {
		return nil, err
	}
	var (
		body any
		dist *Distribution
	)
	if c.ConvType == "dm" {
		body, err = d.sealDR(ctx, c, plaintext)
	} else {
		body, dist, err = d.sealGroup(ctx, c, plaintext)
	}
	if err != nil {
		return nil, err
	}
	sent, err := d.postMessage(ctx, conv, body)
	if err != nil {
		return nil, err
	}
	sent.Distribution = dist
	return sent, nil
}

// SendPlaintext is the explicit, signed plaintext DM. Whether to ever call it
// is the program's decision; Send never does.
func (d *Dms) SendPlaintext(ctx context.Context, conv, content string) (*Sent, error) {
	c, err := d.Conversation(ctx, conv)
	if err != nil {
		return nil, err
	}
	v2, err := d.c.HasCapability(ctx, "dms.plaintext.v2")
	if err != nil {
		return nil, err
	}
	var rnd [16]byte
	if _, err := rand.Read(rnd[:]); err != nil {
		return nil, err
	}
	rnd[6] = rnd[6]&0x0f | 0x40
	rnd[8] = rnd[8]&0x3f | 0x80
	messageID := fmt.Sprintf("%x-%x-%x-%x-%x", rnd[0:4], rnd[4:6], rnd[6:8], rnd[8:10], rnd[10:])
	createdAt := uint64(time.Now().Unix())
	var signing []byte
	if v2 {
		signing = FederatedPlaintextDMV2SigningBytes(conv, c.ConvType, content, messageID, createdAt, c.Members)
	} else {
		signing = FederatedPlaintextDMSigningBytes(conv, c.ConvType, content)
	}
	body := map[string]any{
		"content":             content,
		"attachments":         []any{},
		"plaintext_signature": hex.EncodeToString(d.c.Identity.Sign(signing)),
	}
	if v2 {
		body["message_id"] = messageID
		body["created_at"] = createdAt
	}
	return d.postMessage(ctx, conv, body)
}

func (d *Dms) postMessage(ctx context.Context, conv string, body any) (*Sent, error) {
	var v struct {
		ID        string `json:"id"`
		CreatedAt int64  `json:"created_at"`
	}
	if err := d.c.jsonCall(ctx, http.MethodPost, "/conversations/"+url.PathEscape(conv)+"/messages", nil, body, &v); err != nil {
		return nil, err
	}
	return &Sent{ID: v.ID, CreatedAt: v.CreatedAt}, nil
}

func (d *Dms) sealDR(ctx context.Context, c *Conversation, plaintext []byte) (any, error) {
	me := d.me()
	peer := ""
	for _, m := range c.Members {
		if m != me {
			peer = m
			break
		}
	}
	if peer == "" {
		return nil, dmErr(ErrDMMalformed, "conversation has no other member")
	}
	key := "dr/" + c.ID
	session, err := getJSON[drSession](d.c.store, key)
	if err != nil {
		return nil, err
	}
	if session == nil {
		their, err := d.c.PeerDHKey(ctx, peer)
		if err != nil {
			return nil, err
		}
		if session, err = newDRInitiator(d.c.Identity.dhSecret(), their, c.ID, randomKey()); err != nil {
			return nil, err
		}
	}
	dhPub := session.DHSPub
	ct, index, prev, err := session.seal(plaintext)
	if err != nil {
		return nil, err
	}
	// Persisted before the POST: a key is never used twice, and a failed send
	// leaves a gap the receiver skips over.
	if err := putJSON(d.c.store, key, session); err != nil {
		return nil, err
	}
	ctHex := hex.EncodeToString(ct)
	sig := hex.EncodeToString(d.c.Identity.Sign(DREnvelopeSigningBytes(c.ID, index, prev, ctHex, dhPub)))
	return map[string]any{"encrypted_envelope": map[string]any{
		"sender_pubkey": me, "conv_id": c.ID, "ciphertext_hex": ctHex, "nonce_hex": "",
		"dh_pubkey_hex": dhPub, "signature_hex": sig, "v": 2, "message_index": index, "prev_count": prev,
	}}, nil
}

func (d *Dms) sealGroup(ctx context.Context, c *Conversation, plaintext []byte) (any, *Distribution, error) {
	ownKey := "group-own/" + c.ID
	own, err := getJSON[groupOwn](d.c.store, ownKey)
	if err != nil {
		return nil, nil, err
	}
	var dist *Distribution
	if own == nil {
		if own, dist, err = d.newChain(ctx, c, 1); err != nil {
			return nil, nil, err
		}
	}
	iteration, version := own.Iteration, own.Version
	chain, err := h32(own.ChainKey)
	if err != nil {
		return nil, nil, err
	}
	ct, nonce, next := groupMessageSeal(chain, iteration, plaintext)
	own.ChainKey = hex.EncodeToString(next[:])
	own.Iteration++
	if err := putJSON(d.c.store, ownKey, own); err != nil {
		return nil, nil, err
	}
	ctHex, nonceHex := hex.EncodeToString(ct), hex.EncodeToString(nonce[:])
	sig := hex.EncodeToString(d.c.Identity.Sign(GroupDMEnvelopeSigningBytes(c.ID, version, iteration, ctHex, nonceHex)))
	return map[string]any{"group_encrypted_envelope": map[string]any{
		"sender_pubkey": d.me(), "conv_id": c.ID, "sender_key_version": version, "iteration": iteration,
		"ciphertext_hex": ctHex, "nonce_hex": nonceHex, "signature_hex": sig,
	}}, dist, nil
}

// newChain makes a fresh chain at version, distributes it to every other
// member and stores it once the hub accepted the distribution.
func (d *Dms) newChain(ctx context.Context, c *Conversation, version uint32) (*groupOwn, *Distribution, error) {
	ck := randomKey()
	own := &groupOwn{Version: version, ChainKey: hex.EncodeToString(ck[:])}
	dist, err := d.distribute(ctx, c, own)
	if err != nil {
		return nil, nil, err
	}
	if err := putJSON(d.c.store, "group-own/"+c.ID, own); err != nil {
		return nil, nil, err
	}
	return own, dist, nil
}

func (d *Dms) distribute(ctx context.Context, c *Conversation, own *groupOwn) (*Distribution, error) {
	me := d.me()
	myDH := d.c.Identity.dhSecret()
	chain, err := h32(own.ChainKey)
	if err != nil {
		return nil, err
	}
	dist := &Distribution{Version: own.Version}
	var blobs []map[string]any
	var pairs []SenderKeyRecipient
	for _, member := range c.Members {
		if member == me {
			continue
		}
		their, err := d.c.PeerDHKey(ctx, member)
		if err != nil {
			if perMessage(err) {
				dist.Skipped = append(dist.Skipped, SkippedMember{PublicKey: member, Err: err})
				continue
			}
			return nil, err
		}
		var nonce [12]byte
		if _, err := rand.Read(nonce[:]); err != nil {
			return nil, err
		}
		wrapped, err := groupKeyWrap(myDH, their, c.ID, chain, own.Iteration, nonce)
		if err != nil {
			return nil, cryptoErr(err)
		}
		w := hex.EncodeToString(wrapped)
		blobs = append(blobs, map[string]any{
			"recipient_pubkey": member, "wrapped_key_hex": w,
			"wrap_nonce_hex": hex.EncodeToString(nonce[:]), "iteration": own.Iteration,
		})
		pairs = append(pairs, SenderKeyRecipient{PublicKey: member, WrappedKeyHex: w})
		dist.Delivered = append(dist.Delivered, member)
	}
	if blobs == nil {
		blobs = []map[string]any{}
	}
	sig := hex.EncodeToString(d.c.Identity.Sign(SenderKeyDistSigningBytes(c.ID, own.Version, pairs)))
	err = d.c.jsonCall(ctx, http.MethodPut, "/conversations/"+url.PathEscape(c.ID)+"/sender-keys", nil, map[string]any{
		"sender_key_version": own.Version, "recipients": blobs, "signature_hex": sig,
	}, nil)
	if err != nil {
		return nil, err
	}
	return dist, nil
}

// RotateGroupKey makes a new sender key (version + 1) and re-distributes it
// to the members now in the conversation, so someone who left cannot read what
// follows. Earlier messages stay readable: peers keep a chain per version.
func (d *Dms) RotateGroupKey(ctx context.Context, conv string) (*Distribution, error) {
	d.s.mu.Lock()
	defer d.s.mu.Unlock()
	c, err := d.Conversation(ctx, conv)
	if err != nil {
		return nil, err
	}
	old, err := getJSON[groupOwn](d.c.store, "group-own/"+conv)
	if err != nil {
		return nil, err
	}
	version := uint32(1)
	if old != nil {
		version = old.Version + 1
	}
	_, dist, err := d.newChain(ctx, c, version)
	return dist, err
}

// HandleEvent rotates the sender key on a dm_member_changed event when this
// program has one for that conversation; it is a no-op (nil, nil) for every
// other event. Call it with the events you read, or call RotateGroupKey
// yourself.
func (d *Dms) HandleEvent(ctx context.Context, ev Event) (*Distribution, error) {
	changed, ok := ev.(*DMMemberChanged)
	if !ok {
		return nil, nil
	}
	own, err := getJSON[groupOwn](d.c.store, "group-own/"+changed.ConversationID)
	if err != nil || own == nil {
		return nil, err
	}
	return d.RotateGroupKey(ctx, changed.ConversationID)
}

// signedChange is the signed membership change the hub's
// dms.group.signedmembers wants; nil on a hub without it.
func (d *Dms) signedChange(ctx context.Context, conv string, added, removed []string) (map[string]any, error) {
	ok, err := d.c.HasCapability(ctx, "dms.group.signedmembers")
	if err != nil || !ok {
		return nil, err
	}
	issuedAt := uint64(time.Now().Unix())
	sig := d.c.Identity.Sign(DMMemberChangeSigningBytes(conv, d.me(), added, removed, issuedAt))
	return map[string]any{"issued_at": issuedAt, "signature": hex.EncodeToString(sig)}, nil
}

// AddMembers adds members (one request each, as the hub takes them), then
// rotates the sender key if this program holds one.
func (d *Dms) AddMembers(ctx context.Context, conv string, members []string) error {
	for _, m := range members {
		body := map[string]any{"public_key": m}
		signed, err := d.signedChange(ctx, conv, []string{m}, nil)
		if err != nil {
			return err
		}
		if signed != nil {
			body["signed"] = signed
		}
		if err := d.c.jsonCall(ctx, http.MethodPost, "/conversations/"+url.PathEscape(conv)+"/members", nil, body, nil); err != nil {
			return err
		}
	}
	own, err := getJSON[groupOwn](d.c.store, "group-own/"+conv)
	if err != nil || own == nil {
		return err
	}
	_, err = d.RotateGroupKey(ctx, conv)
	return err
}

// Leave leaves a group. The hub lets a member remove only themselves.
func (d *Dms) Leave(ctx context.Context, conv string) error {
	me := d.me()
	signed, err := d.signedChange(ctx, conv, nil, []string{me})
	if err != nil {
		return err
	}
	var body any
	if signed != nil {
		body = signed
	}
	return d.c.jsonCall(ctx, http.MethodDelete, "/conversations/"+url.PathEscape(conv)+"/members/"+url.PathEscape(me), nil, body, nil)
}

// ---------------------------------------------------------------------------
// Receiving
// ---------------------------------------------------------------------------

type dmRow struct {
	ID                     string   `json:"id"`
	ConversationID         string   `json:"conversation_id"`
	Sender                 string   `json:"sender"`
	SenderName             *string  `json:"sender_name"`
	Content                *string  `json:"content"`
	CreatedAt              int64    `json:"created_at"`
	Attachments            []any    `json:"attachments"`
	EncryptedEnvelope      envelope `json:"encrypted_envelope"`
	GroupEncryptedEnvelope envelope `json:"group_encrypted_envelope"`
}

// Messages reads a page of a conversation, each message decrypted. Transient
// hub failures are the call's error; a message that cannot be read is that
// message's Err.
func (d *Dms) Messages(ctx context.Context, conv string, page MessagesPage) ([]DMMessage, error) {
	q := url.Values{}
	if page.Limit > 0 {
		q.Set("limit", strconv.Itoa(page.Limit))
	}
	if page.Cursor != "" {
		q.Set("cursor", page.Cursor)
	}
	rows, err := d.rows(ctx, conv, q)
	if err != nil {
		return nil, err
	}
	out := make([]DMMessage, 0, len(rows))
	for _, row := range rows {
		m, err := d.readRow(ctx, conv, row)
		if err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, nil
}

// Poll returns the messages this handle has not returned yet. The first call
// for a conversation returns its newest page, so a program that only wants
// what arrives from now on calls SkipExisting first. The hub's dm event says a
// message arrived; Poll fetches it.
func (d *Dms) Poll(ctx context.Context, conv string) ([]DMMessage, error) {
	rows, err := d.rows(ctx, conv, url.Values{"limit": {"100"}})
	if err != nil {
		return nil, err
	}
	var out []DMMessage
	for _, row := range rows {
		if d.isSeen(row.ID) {
			continue
		}
		m, err := d.readRow(ctx, conv, row)
		if err != nil {
			return nil, err
		}
		out = append(out, m)
		d.markSeen(row.ID)
	}
	return out, nil
}

// SkipExisting marks what is in the conversation now as delivered, without
// decrypting it: Poll then returns only later messages.
func (d *Dms) SkipExisting(ctx context.Context, conv string) error {
	rows, err := d.rows(ctx, conv, url.Values{"limit": {"100"}})
	if err != nil {
		return err
	}
	for _, row := range rows {
		d.markSeen(row.ID)
	}
	return nil
}

func (d *Dms) rows(ctx context.Context, conv string, q url.Values) ([]dmRow, error) {
	var rows []dmRow
	if err := d.c.jsonCall(ctx, http.MethodGet, "/conversations/"+url.PathEscape(conv)+"/messages", q, nil, &rows); err != nil {
		return nil, err
	}
	return rows, nil
}

func (d *Dms) isSeen(id string) bool {
	d.s.cacheMu.Lock()
	defer d.s.cacheMu.Unlock()
	_, ok := d.s.seen[id]
	return ok
}

func (d *Dms) markSeen(id string) {
	d.s.cacheMu.Lock()
	defer d.s.cacheMu.Unlock()
	if _, ok := d.s.seen[id]; ok {
		return
	}
	d.s.seen[id] = struct{}{}
	d.s.seenOrder = append(d.s.seenOrder, id)
	if len(d.s.seenOrder) > seenCap {
		delete(d.s.seen, d.s.seenOrder[0])
		d.s.seenOrder = d.s.seenOrder[1:]
	}
}

func (d *Dms) readRow(ctx context.Context, conv string, row dmRow) (DMMessage, error) {
	m := DMMessage{
		ID: row.ID, ConversationID: row.ConversationID, Sender: row.Sender, SenderName: row.SenderName,
		CreatedAt: row.CreatedAt, Encrypted: row.EncryptedEnvelope != nil || row.GroupEncryptedEnvelope != nil,
	}
	plain, err := d.openRow(ctx, conv, row)
	if err != nil && !perMessage(err) {
		return m, err
	}
	m.Content, m.Err = plain, err
	return m, nil
}

func (d *Dms) openRow(ctx context.Context, conv string, row dmRow) (DMPlaintext, error) {
	d.s.cacheMu.Lock()
	hit, ok := d.s.plain[row.ID]
	d.s.cacheMu.Unlock()
	if ok {
		return hit, nil
	}
	d.s.mu.Lock()
	defer d.s.mu.Unlock()
	var plain DMPlaintext
	switch {
	case row.EncryptedEnvelope != nil:
		if err := verifyEnvelope(conv, row.EncryptedEnvelope, row.Sender); err != nil {
			return plain, err
		}
		if row.Sender == d.me() {
			return plain, dmErr(ErrDMOwnMessage, "")
		}
		var raw []byte
		var err error
		if v, _ := row.EncryptedEnvelope["v"].(float64); v == 2 {
			raw, err = d.openDR(ctx, conv, row.EncryptedEnvelope, row.Sender)
		} else {
			raw, err = d.openV1(conv, row.EncryptedEnvelope)
		}
		if err != nil {
			return plain, err
		}
		if plain, err = parsePlaintext(raw); err != nil {
			return plain, err
		}
	case row.GroupEncryptedEnvelope != nil:
		if err := verifyEnvelope(conv, row.GroupEncryptedEnvelope, row.Sender); err != nil {
			return plain, err
		}
		if row.Sender == d.me() {
			return plain, dmErr(ErrDMOwnMessage, "")
		}
		raw, err := d.openGroup(ctx, conv, row.GroupEncryptedEnvelope, row.Sender)
		if err != nil {
			return plain, err
		}
		if plain, err = parsePlaintext(raw); err != nil {
			return plain, err
		}
	default:
		plain = DMPlaintext{Attachments: row.Attachments}
		if row.Content != nil {
			plain.Content = *row.Content
		}
	}
	d.s.cacheMu.Lock()
	defer d.s.cacheMu.Unlock()
	if _, ok := d.s.plain[row.ID]; !ok {
		d.s.plain[row.ID] = plain
		d.s.order = append(d.s.order, row.ID)
		if len(d.s.order) > plainCache {
			delete(d.s.plain, d.s.order[0])
			d.s.order = d.s.order[1:]
		}
	}
	return plain, nil
}

func (d *Dms) openV1(conv string, env envelope) ([]byte, error) {
	their, ok := hex32(env.text("dh_pubkey_hex"))
	if !ok {
		return nil, dmErr(ErrDMMalformed, "dh_pubkey_hex")
	}
	key, err := dmKeyV1(d.c.Identity.dhSecret(), their, conv)
	if err != nil {
		return nil, cryptoErr(err)
	}
	nonce, err := env.hexField("nonce_hex")
	if err != nil {
		return nil, err
	}
	ct, err := env.hexField("ciphertext_hex")
	if err != nil {
		return nil, err
	}
	out, err := aeadOpen(key, nonce, ct, nil)
	if err != nil {
		return nil, dmErr(ErrDMDecryptionFailed, "")
	}
	return out, nil
}

func (d *Dms) openDR(ctx context.Context, conv string, env envelope, sender string) ([]byte, error) {
	key := "dr/" + conv
	dhPub := env.text("dh_pubkey_hex")
	session, err := getJSON[drSession](d.c.store, key)
	if err != nil {
		return nil, err
	}
	if session == nil {
		// First inbound message of a conversation this side never sent in:
		// responder-init from the sender's published key.
		their, err := d.c.PeerDHKey(ctx, sender)
		if err != nil {
			return nil, err
		}
		if session, err = newDRResponder(d.c.Identity.dhSecret(), their, conv, dhPub, randomKey()); err != nil {
			return nil, err
		}
	}
	index, err := env.mustU32("message_index")
	if err != nil {
		return nil, err
	}
	prev, _ := env.u32("prev_count")
	ct, err := env.hexField("ciphertext_hex")
	if err != nil {
		return nil, err
	}
	plain, err := session.open(dhPub, index, prev, ct)
	if err != nil {
		return nil, err
	}
	if err := putJSON(d.c.store, key, session); err != nil {
		return nil, err
	}
	return plain, nil
}

func (d *Dms) openGroup(ctx context.Context, conv string, env envelope, sender string) ([]byte, error) {
	version, err := env.mustU32("sender_key_version")
	if err != nil {
		return nil, err
	}
	iteration, err := env.mustU32("iteration")
	if err != nil {
		return nil, err
	}
	key := fmt.Sprintf("group-peer/%s/%s/%d", conv, sender, version)
	chain, err := getJSON[groupPeer](d.c.store, key)
	if err != nil {
		return nil, err
	}
	if chain == nil {
		if err := d.refreshSenderKeys(ctx, conv); err != nil {
			return nil, err
		}
		if chain, err = getJSON[groupPeer](d.c.store, key); err != nil {
			return nil, err
		}
	}
	if chain == nil {
		return nil, dmErr(ErrDMKeyNotFound, fmt.Sprintf("%s at version %d", sender, version))
	}
	if chain.Iteration > iteration {
		return nil, dmErr(ErrDMChainAdvanced, "")
	}
	ck, err := h32(chain.ChainKey)
	if err != nil {
		return nil, err
	}
	nonce, err := env.hexField("nonce_hex")
	if err != nil {
		return nil, err
	}
	ct, err := env.hexField("ciphertext_hex")
	if err != nil {
		return nil, err
	}
	out, err := groupMessageOpen(ck, chain.Iteration, iteration, nonce, ct)
	if err != nil {
		return nil, dmErr(ErrDMDecryptionFailed, "")
	}
	return out, nil
}

// refreshSenderKeys unwraps the sender keys the hub holds for this program and
// stores the ones not held yet. A sender whose DH key is missing or changed is
// skipped: its messages then report ErrDMKeyNotFound.
func (d *Dms) refreshSenderKeys(ctx context.Context, conv string) error {
	var entries []struct {
		SenderPubkey     string `json:"sender_pubkey"`
		SenderKeyVersion uint32 `json:"sender_key_version"`
		WrappedKeyHex    string `json:"wrapped_key_hex"`
		WrapNonceHex     string `json:"wrap_nonce_hex"`
	}
	if err := d.c.jsonCall(ctx, http.MethodGet, "/conversations/"+url.PathEscape(conv)+"/sender-keys", nil, nil, &entries); err != nil {
		return err
	}
	myDH := d.c.Identity.dhSecret()
	for _, e := range entries {
		wrapped, err1 := hex.DecodeString(e.WrappedKeyHex)
		nonce, err2 := hex.DecodeString(e.WrapNonceHex)
		if err1 != nil || err2 != nil || e.SenderPubkey == "" {
			continue
		}
		key := fmt.Sprintf("group-peer/%s/%s/%d", conv, e.SenderPubkey, e.SenderKeyVersion)
		held, err := d.c.store.Get(key)
		if err != nil {
			return err
		}
		if held != nil {
			continue
		}
		their, err := d.c.PeerDHKey(ctx, e.SenderPubkey)
		if err != nil {
			if perMessage(err) {
				continue
			}
			return err
		}
		chain, iteration, err := groupKeyUnwrap(myDH, their, conv, nonce, wrapped)
		if err != nil {
			continue
		}
		if err := putJSON(d.c.store, key, groupPeer{ChainKey: hex.EncodeToString(chain[:]), Iteration: iteration}); err != nil {
			return err
		}
	}
	return nil
}
