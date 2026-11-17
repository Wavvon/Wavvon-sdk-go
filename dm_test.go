package wavvon

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"testing"
)

func ratchetPair(t *testing.T) (alice, bob *drSession) {
	t.Helper()
	a, b := key32{0x11}, key32{0x22}
	alice, err := newDRInitiator(a, x25519Pub(b), "c", randomKey())
	if err != nil {
		t.Fatal(err)
	}
	bob, err = newDRResponder(b, x25519Pub(a), "c", alice.DHSPub, randomKey())
	if err != nil {
		t.Fatal(err)
	}
	return alice, bob
}

func clone(s *drSession) *drSession {
	c := *s
	c.MKSkipped = map[string]string{}
	for k, v := range s.MKSkipped {
		c.MKSkipped[k] = v
	}
	return &c
}

type sentMsg struct {
	dh        string
	idx, prev uint32
	ct        []byte
}

func sealN(t *testing.T, s *drSession, text string) sentMsg {
	t.Helper()
	dh := s.DHSPub
	ct, idx, prev, err := s.seal([]byte(text))
	if err != nil {
		t.Fatal(err)
	}
	return sentMsg{dh, idx, prev, ct}
}

func TestRatchetRoundTripsOutOfOrderAndAcrossAReply(t *testing.T) {
	alice, bob := ratchetPair(t)
	sent := []sentMsg{sealN(t, alice, "m0"), sealN(t, alice, "m1"), sealN(t, alice, "m2")}
	for _, i := range []int{2, 0, 1} {
		m := sent[i]
		got, err := bob.open(m.dh, m.idx, m.prev, m.ct)
		if err != nil || string(got) != "m"+string(rune('0'+i)) {
			t.Fatalf("message %d: %q, %v", i, got, err)
		}
	}
	reply := sealN(t, bob, "reply")
	if got, err := alice.open(reply.dh, reply.idx, reply.prev, reply.ct); err != nil || string(got) != "reply" {
		t.Fatalf("reply: %q, %v", got, err)
	}
	again := sealN(t, alice, "again")
	if again.dh == sent[0].dh {
		t.Fatal("alice kept her ratchet key after a reply")
	}
	if got, err := bob.open(again.dh, again.idx, again.prev, again.ct); err != nil || string(got) != "again" {
		t.Fatalf("after the step: %q, %v", got, err)
	}
}

func TestRatchetRefusesReplayAndTamperAndHugeGaps(t *testing.T) {
	alice, bob := ratchetPair(t)
	m := sealN(t, alice, "once")
	before := clone(bob)
	if _, err := bob.open(m.dh, m.idx, m.prev, m.ct); err != nil {
		t.Fatal(err)
	}
	if _, err := clone(bob).open(m.dh, m.idx, m.prev, m.ct); !errors.Is(err, ErrDMDecryptionFailed) {
		t.Fatalf("replay: %v", err)
	}
	bad := bytes.Clone(m.ct)
	bad[0] ^= 1
	if _, err := before.open(m.dh, m.idx, m.prev, bad); !errors.Is(err, ErrDMDecryptionFailed) {
		t.Fatalf("tamper: %v", err)
	}
	_, fresh := ratchetPair(t)
	if _, err := fresh.open(alice.DHSPub, 5000, 0, make([]byte, 32)); !errors.Is(err, ErrDMTooManySkipped) {
		t.Fatalf("gap: %v", err)
	}
}

func TestEnvelopeNotSignedByItsNamedSenderIsRefused(t *testing.T) {
	priv := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, 32))
	sender := hex.EncodeToString(priv.Public().(ed25519.PublicKey))
	sig := ed25519.Sign(priv, DREnvelopeSigningBytes("c", 1, 0, "aa", "bb"))
	env := envelope{
		"sender_pubkey": sender, "v": float64(2), "message_index": float64(1), "prev_count": float64(0),
		"ciphertext_hex": "aa", "dh_pubkey_hex": "bb", "signature_hex": hex.EncodeToString(sig),
	}
	if err := verifyEnvelope("c", env, sender); err != nil {
		t.Fatal(err)
	}
	if err := verifyEnvelope("other-conv", env, sender); !errors.Is(err, ErrDMNotSignedBySender) {
		t.Fatalf("other conversation: %v", err)
	}
	if err := verifyEnvelope("c", env, "someone-else"); !errors.Is(err, ErrDMNotSignedBySender) {
		t.Fatalf("other sender: %v", err)
	}
}

func TestMemoryStoreCopiesAndForgets(t *testing.T) {
	s := &MemoryStore{}
	if v, err := s.Get("k"); v != nil || err != nil {
		t.Fatalf("absent key: %v, %v", v, err)
	}
	in := []byte("v")
	_ = s.Put("k", in)
	in[0] = 'x'
	if v, _ := s.Get("k"); string(v) != "v" {
		t.Fatalf("store kept the caller's slice: %q", v)
	}
	_ = s.Delete("k")
	if v, _ := s.Get("k"); v != nil {
		t.Fatal("deleted key still there")
	}
}
