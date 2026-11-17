package wavvon

// Asserts every DM and voice vector of Wavvon-server's wire-vectors.json
// (sdk-dm.md section 6, sdk-voice.md section 2): the signing bytes and
// signatures, and the encryption itself.

import (
	"bytes"
	"encoding/hex"
	"strconv"
	"testing"
)

func (v vector) strs(path ...string) []string {
	var cur any = map[string]any(v)
	for _, p := range path {
		cur = cur.(map[string]any)[p]
	}
	var out []string
	for _, x := range cur.([]any) {
		out = append(out, x.(string))
	}
	return out
}

func (v vector) u(path ...string) uint64 {
	n, err := strconv.ParseUint(v.s(path...), 10, 64)
	if err != nil {
		panic(err)
	}
	return n
}

func mustHex32(t *testing.T, s string) key32 {
	t.Helper()
	k, ok := hex32(s)
	if !ok {
		t.Fatalf("not 32 bytes of hex: %q", s)
	}
	return k
}

func (v vector) k(t *testing.T, path ...string) key32 { return mustHex32(t, v.s(path...)) }

func same(t *testing.T, what string, got []byte, want string) {
	t.Helper()
	if hex.EncodeToString(got) != want {
		t.Fatalf("%s:\n got  %x\n want %s", what, got, want)
	}
}

func seedOf(t *testing.T, hexSeed string) []byte {
	t.Helper()
	return unhex(t, hexSeed)
}

func signs(t *testing.T, v vector, signing []byte) {
	t.Helper()
	same(t, "signing bytes", signing, v.s("signing_bytes"))
	id, err := IdentityFromHexSeed(v.s("inputs", "signer_seed"))
	if err != nil {
		t.Fatal(err)
	}
	same(t, "signature", id.Sign(signing), v.s("signature"))
}

func TestConformanceDMAndVoice(t *testing.T) {
	vec := loadVectors(t)

	t.Run("master_dh_pubkey", func(t *testing.T) {
		v := vec("master_dh_pubkey")
		id, _ := IdentityFromHexSeed(v.s("inputs", "seed"))
		if id.DHPublicKeyHex() != v.s("dh_pubkey") {
			t.Fatalf("got %s", id.DHPublicKeyHex())
		}
	})

	t.Run("dh_key_record", func(t *testing.T) {
		v := vec("dh_key_record")
		signs(t, v, DHKeyRecordSigningBytes(v.s("inputs", "pubkey"), v.s("inputs", "dh_pubkey")))
	})

	t.Run("dm_envelope", func(t *testing.T) {
		v := vec("dm_envelope")
		signs(t, v, DMEnvelopeSigningBytes(v.s("inputs", "conversation_id"), v.s("inputs", "ciphertext"), v.s("inputs", "nonce"), v.s("inputs", "sender_dh_pubkey")))
	})

	t.Run("dr_envelope", func(t *testing.T) {
		v := vec("dr_envelope")
		signs(t, v, DREnvelopeSigningBytes(v.s("inputs", "conversation_id"), uint32(v.u("inputs", "message_index")), uint32(v.u("inputs", "prev_count")), v.s("inputs", "ciphertext"), v.s("inputs", "dh_pubkey")))
	})

	t.Run("group_dm_envelope", func(t *testing.T) {
		v := vec("group_dm_envelope")
		signs(t, v, GroupDMEnvelopeSigningBytes(v.s("inputs", "conversation_id"), uint32(v.u("inputs", "sender_key_version")), uint32(v.u("inputs", "iteration")), v.s("inputs", "ciphertext"), v.s("inputs", "nonce")))
	})

	t.Run("sender_key_dist", func(t *testing.T) {
		v := vec("sender_key_dist")
		var rs []SenderKeyRecipient
		for _, r := range v["inputs"].(map[string]any)["recipients"].([]any) {
			p := r.([]any)
			rs = append(rs, SenderKeyRecipient{PublicKey: p[0].(string), WrappedKeyHex: p[1].(string)})
		}
		signs(t, v, SenderKeyDistSigningBytes(v.s("inputs", "conversation_id"), uint32(v.u("inputs", "version")), rs))
	})

	t.Run("dm_member_change", func(t *testing.T) {
		v := vec("dm_member_change")
		signs(t, v, DMMemberChangeSigningBytes(v.s("inputs", "conversation_id"), v.s("inputs", "actor"), v.strs("inputs", "added"), v.strs("inputs", "removed"), v.u("inputs", "timestamp")))
	})

	t.Run("federated_plaintext_dm", func(t *testing.T) {
		v := vec("federated_plaintext_dm")
		signs(t, v, FederatedPlaintextDMSigningBytes(v.s("inputs", "conversation_id"), v.s("inputs", "kind"), v.s("inputs", "content")))
	})

	t.Run("federated_plaintext_dm_v2", func(t *testing.T) {
		v := vec("federated_plaintext_dm_v2")
		signs(t, v, FederatedPlaintextDMV2SigningBytes(v.s("inputs", "conversation_id"), v.s("inputs", "kind"), v.s("inputs", "content"), v.s("inputs", "message_id"), v.u("inputs", "created_at"), v.strs("inputs", "members")))
	})

	t.Run("subkey_cert", func(t *testing.T) {
		v := vec("subkey_cert")
		in := v["inputs"].(map[string]any)
		if in["not_after"] != nil {
			t.Fatal("vector has an expiry; this test covers none")
		}
		signs(t, v, SubkeyCertSigningBytes(v.s("inputs", "master_pubkey"), v.s("inputs", "subkey_pubkey"), v.s("inputs", "device_label"), v.u("inputs", "issued_at"), nil, v.strs("inputs", "fallback_hubs")))
		cert := SubkeyCert{
			MasterPubkey: v.s("inputs", "master_pubkey"), SubkeyPubkey: v.s("inputs", "subkey_pubkey"),
			DeviceLabel: v.s("inputs", "device_label"), IssuedAt: v.u("inputs", "issued_at"), Signature: v.s("signature"),
		}
		if err := cert.Verify(); err != nil {
			t.Fatal(err)
		}
		cert.DeviceLabel = "other"
		if cert.Verify() == nil {
			t.Fatal("a changed cert verified")
		}
	})

	t.Run("dm_key_v1", func(t *testing.T) {
		v := vec("dm_key_v1")
		a, b := dhSecretFromSeed(seedOf(t, v.s("inputs", "alice_seed"))), dhSecretFromSeed(seedOf(t, v.s("inputs", "bob_seed")))
		conv := v.s("inputs", "conversation_id")
		key, err := dmKeyV1(a, x25519Pub(b), conv)
		if err != nil {
			t.Fatal(err)
		}
		same(t, "key", key[:], v.s("key"))
		other, _ := dmKeyV1(b, x25519Pub(a), conv)
		if other != key {
			t.Fatal("the key is not symmetric")
		}
		nonce := [12]byte(unhex(t, v.s("inputs", "nonce")))
		ct := aeadSeal(key, nonce, []byte(v.s("inputs", "plaintext")), nil)
		same(t, "ciphertext", ct, v.s("ciphertext"))
		if out, err := aeadOpen(key, nonce[:], ct, nil); err != nil || string(out) != v.s("inputs", "plaintext") {
			t.Fatalf("open: %q, %v", out, err)
		}
	})

	t.Run("dr_session", func(t *testing.T) {
		v := vec("dr_session")
		aSec, bSec := dhSecretFromSeed(seedOf(t, v.s("inputs", "alice_seed"))), dhSecretFromSeed(seedOf(t, v.s("inputs", "bob_seed")))
		aEph, bEph := v.k(t, "inputs", "alice_eph_secret"), v.k(t, "inputs", "bob_eph_secret")
		conv := v.s("inputs", "conversation_id")
		rk0, _ := drRootKey(aSec, x25519Pub(bSec), conv)
		same(t, "rk0", rk0[:], v.s("rk0"))
		alice, err := drInitiatorInit(aSec, x25519Pub(bSec), conv, aEph)
		if err != nil {
			t.Fatal(err)
		}
		same(t, "alice_eph_pub", alice.ephPub[:], v.s("alice_eph_pub"))
		same(t, "alice_rk", alice.rk[:], v.s("alice_rk"))
		same(t, "alice_cks", alice.cks[:], v.s("alice_cks"))
		mk, next := drKDFCK(alice.cks)
		same(t, "message_key", mk[:], v.s("message_key"))
		n := drNonce(mk)
		same(t, "nonce", n[:], v.s("nonce"))
		same(t, "next_cks", next[:], v.s("next_cks"))
		ct := drMessageSeal(mk, []byte(v.s("inputs", "plaintext")))
		same(t, "ciphertext", ct, v.s("ciphertext"))

		bob, err := drResponderInit(bSec, x25519Pub(aSec), conv, alice.ephPub, bEph)
		if err != nil {
			t.Fatal(err)
		}
		same(t, "bob_rk", bob.rk[:], v.s("bob_rk"))
		same(t, "bob_ckr", bob.ckr[:], v.s("bob_ckr"))
		same(t, "bob_cks", bob.cks[:], v.s("bob_cks"))
		same(t, "bob_eph_pub", bob.ephPub[:], v.s("bob_eph_pub"))
		bmk, _ := drKDFCK(bob.ckr)
		if out, err := drMessageOpen(bmk, ct); err != nil || string(out) != v.s("inputs", "plaintext") {
			t.Fatalf("bob opens message 0: %q, %v", out, err)
		}

		rmk, _ := drKDFCK(bob.cks)
		same(t, "reply_message_key", rmk[:], v.s("reply_message_key"))
		reply := drMessageSeal(rmk, []byte(v.s("inputs", "reply_plaintext")))
		same(t, "reply_ciphertext", reply, v.s("reply_ciphertext"))
		d, _ := x25519(aEph, bob.ephPub)
		stepRK, stepCKR := drKDFRK(alice.rk, d)
		same(t, "reply_step_rk", stepRK[:], v.s("reply_step_rk"))
		same(t, "reply_step_ckr", stepCKR[:], v.s("reply_step_ckr"))
		amk, _ := drKDFCK(stepCKR)
		if out, err := drMessageOpen(amk, reply); err != nil || string(out) != v.s("inputs", "reply_plaintext") {
			t.Fatalf("alice opens the reply: %q, %v", out, err)
		}
	})

	t.Run("group_ratchet", func(t *testing.T) {
		v := vec("group_ratchet")
		chain, it := v.k(t, "inputs", "chain_key"), uint32(v.u("inputs", "iteration"))
		mk := groupMsgKey(chain, it)
		same(t, "message_key", mk[:], v.s("message_key"))
		next := groupNextChainKey(chain, it)
		same(t, "next_chain_key", next[:], v.s("next_chain_key"))
		ct, nonce, _ := groupMessageSeal(chain, it, []byte(v.s("inputs", "plaintext")))
		same(t, "nonce", nonce[:], v.s("nonce"))
		same(t, "ciphertext", ct, v.s("ciphertext"))
		// A chain held at iteration 0 advances to 2; one held past it cannot read.
		if out, err := groupMessageOpen(chain, it, it, nonce[:], ct); err != nil || string(out) != v.s("inputs", "plaintext") {
			t.Fatalf("open: %q, %v", out, err)
		}
		if _, err := groupMessageOpen(chain, it+1, it, nonce[:], ct); err == nil {
			t.Fatal("a message before the held iteration opened")
		}
	})

	t.Run("group_key_wrap", func(t *testing.T) {
		v := vec("group_key_wrap")
		s, r := dhSecretFromSeed(seedOf(t, v.s("inputs", "sender_seed"))), dhSecretFromSeed(seedOf(t, v.s("inputs", "recipient_seed")))
		conv, nonce := v.s("inputs", "conversation_id"), [12]byte(unhex(t, v.s("inputs", "nonce")))
		chain, it := v.k(t, "inputs", "chain_key"), uint32(v.u("inputs", "iteration"))
		ct, err := groupKeyWrap(s, x25519Pub(r), conv, chain, it, nonce)
		if err != nil {
			t.Fatal(err)
		}
		same(t, "ciphertext", ct, v.s("ciphertext"))
		gotChain, gotIt, err := groupKeyUnwrap(r, x25519Pub(s), conv, nonce[:], ct)
		if err != nil || gotChain != chain || gotIt != it {
			t.Fatalf("unwrap: %x %d, %v", gotChain, gotIt, err)
		}
	})

	t.Run("voice_key_wrap", func(t *testing.T) {
		v := vec("voice_key_wrap")
		sender, _ := IdentityFromHexSeed(v.s("inputs", "sender_seed"))
		recipient, _ := IdentityFromHexSeed(v.s("inputs", "recipient_seed"))
		key, salt := v.k(t, "inputs", "sender_key"), [4]byte(unhex(t, v.s("inputs", "nonce_salt")))
		nonce, keyID := [12]byte(unhex(t, v.s("inputs", "wrap_nonce"))), uint32(v.u("inputs", "key_id"))
		channel := v.s("inputs", "channel_id")
		recipientDH := x25519Pub(recipient.dhSecret())
		ct, err := voiceKeyWrapWithNonce(sender.key.Seed(), recipientDH, channel, key, salt, keyID, nonce)
		if err != nil {
			t.Fatal(err)
		}
		same(t, "ciphertext", ct, v.s("ciphertext"))
		gotKey, gotSalt, gotID, err := VoiceKeyUnwrap(recipient, x25519Pub(sender.dhSecret()), channel, ct, nonce[:])
		if err != nil || gotKey != key || gotSalt != salt || gotID != keyID {
			t.Fatalf("unwrap: %x %x %d, %v", gotKey, gotSalt, gotID, err)
		}
		if _, _, _, err := VoiceKeyUnwrap(recipient, x25519Pub(sender.dhSecret()), "another-channel", ct, nonce[:]); err == nil {
			t.Fatal("a wrap opened on the wrong channel")
		}
		ct2, nonce2, err := VoiceKeyWrap(sender, recipientDH, channel, key, salt, keyID)
		if err != nil || nonce2 == nonce {
			t.Fatalf("VoiceKeyWrap: %v", err)
		}
		if k, _, _, err := VoiceKeyUnwrap(recipient, x25519Pub(sender.dhSecret()), channel, ct2, nonce2[:]); err != nil || k != key {
			t.Fatalf("round trip: %v", err)
		}
	})

	for _, name := range []string{"voice_packet_ctr0", "voice_packet_ctr7"} {
		t.Run(name, func(t *testing.T) {
			v := vec(name)
			key, salt := v.k(t, "inputs", "sender_key"), [4]byte(unhex(t, v.s("inputs", "nonce_salt")))
			opus := unhex(t, v.s("inputs", "opus"))
			keyID, ctr, ts := uint32(v.u("inputs", "key_id")), v.u("inputs", "counter"), uint32(v.u("inputs", "timestamp"))
			packet := VoicePacketSeal(key, salt, keyID, ctr, ts, opus)
			same(t, "packet", packet, v.s("packet"))
			gk, gc, gt, gopus, err := VoicePacketOpen(key, salt, packet)
			if err != nil || gk != keyID || gc != ctr || gt != ts || !bytes.Equal(gopus, opus) {
				t.Fatalf("open: %d %d %d %x, %v", gk, gc, gt, gopus, err)
			}
			packet[3] ^= 1
			if _, _, _, _, err := VoicePacketOpen(key, salt, packet); err == nil {
				t.Fatal("a packet with a tampered header opened")
			}
			if _, _, _, _, err := VoicePacketOpen(key, salt, packet[:20]); err == nil {
				t.Fatal("a short packet opened")
			}
		})
	}
}
