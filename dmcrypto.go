package wavvon

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"io"
)

// The key derivations and AEADs behind E2E DMs and voice, byte for byte as in
// Wavvon-server crates/identity/src/{dm,voice}.rs and pinned by the dm_key_v1,
// dr_session, group_ratchet, group_key_wrap, voice_key_wrap and voice_packet_*
// vectors. Secrets and public keys are raw 32-byte X25519 values; every
// ciphertext is AES-256-GCM with the tag appended. The functions are pure:
// nonces and ephemeral scalars are arguments.

type key32 = [32]byte

func x25519(secret, pub key32) (key32, error) {
	priv, err := ecdh.X25519().NewPrivateKey(secret[:])
	if err != nil {
		return key32{}, err
	}
	peer, err := ecdh.X25519().NewPublicKey(pub[:])
	if err != nil {
		return key32{}, err
	}
	shared, err := priv.ECDH(peer)
	if err != nil {
		return key32{}, err
	}
	return key32(shared), nil
}

func x25519Pub(secret key32) key32 {
	priv, err := ecdh.X25519().NewPrivateKey(secret[:])
	if err != nil {
		panic(err) // a 32-byte scalar is always valid
	}
	return key32(priv.PublicKey().Bytes())
}

func randomKey() key32 {
	var k key32
	if _, err := io.ReadFull(rand.Reader, k[:]); err != nil {
		panic(err)
	}
	return k
}

// hkdfBytes is RFC 5869 HKDF-SHA256, written out because crypto/hkdf needs Go
// 1.24 and x/crypto/hkdf a newer one than this module supports. A nil salt is
// HashLen zero bytes, as the RFC says.
func hkdfBytes(ikm, salt []byte, info string, n int) []byte {
	if salt == nil {
		salt = make([]byte, sha256.Size)
	}
	extract := hmac.New(sha256.New, salt)
	extract.Write(ikm)
	prk := extract.Sum(nil)
	var out, prev []byte
	for i := byte(1); len(out) < n; i++ {
		mac := hmac.New(sha256.New, prk)
		mac.Write(prev)
		mac.Write([]byte(info))
		mac.Write([]byte{i})
		prev = mac.Sum(nil)
		out = append(out, prev...)
	}
	return out[:n]
}

func hkdf32(ikm, salt []byte, info string) key32 { return key32(hkdfBytes(ikm, salt, info, 32)) }

func hkdf64(ikm, salt []byte, info string) (key32, key32) {
	out := hkdfBytes(ikm, salt, info, 64)
	return key32(out[:32]), key32(out[32:])
}

func gcm(key key32) cipher.AEAD {
	block, err := aes.NewCipher(key[:])
	if err != nil {
		panic(err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		panic(err)
	}
	return aead
}

func aeadSeal(key key32, nonce [12]byte, plaintext, aad []byte) []byte {
	return gcm(key).Seal(nil, nonce[:], plaintext, aad)
}

var errDecrypt = errors.New("decryption failed")

func aeadOpen(key key32, nonce, ciphertext, aad []byte) ([]byte, error) {
	if len(nonce) != 12 {
		return nil, errors.New("nonce must be 12 bytes")
	}
	out, err := gcm(key).Open(nil, nonce, ciphertext, aad)
	if err != nil {
		return nil, errDecrypt
	}
	return out, nil
}

// dhSecretFromSeed is SHA-512(seed)[0..32], clamped (vector master_dh_pubkey).
func dhSecretFromSeed(seed []byte) key32 {
	h := sha512.Sum512(seed)
	var s key32
	copy(s[:], h[:32])
	s[0] &= 248
	s[31] &= 127
	s[31] |= 64
	return s
}

// ---- 1:1 v1 (static key; receive only) ----

func dmKeyV1(mySecret, peerPub key32, convID string) (key32, error) {
	shared, err := x25519(mySecret, peerPub)
	if err != nil {
		return key32{}, err
	}
	return hkdf32(shared[:], []byte(convID), "wavvon/dm-key/v1"), nil
}

// ---- 1:1 v2 double ratchet ----

func drRootKey(myStatic, theirStatic key32, convID string) (key32, error) {
	shared, err := x25519(myStatic, theirStatic)
	if err != nil {
		return key32{}, err
	}
	return hkdf32(shared[:], []byte(convID), "wavvon/dr-init/v2"), nil
}

func drKDFRK(rk, dhOut key32) (newRK, ck key32) {
	return hkdf64(dhOut[:], rk[:], "wavvon/dr-rk/v2")
}

func drKDFCK(ck key32) (msgKey, nextCK key32) {
	return hkdf64(ck[:], nil, "wavvon/dr-ck-step/v2")
}

func drNonce(msgKey key32) [12]byte {
	return [12]byte(hkdfBytes(msgKey[:], nil, "wavvon/dr-nonce/v2", 12))
}

func drMessageSeal(msgKey key32, plaintext []byte) []byte {
	return aeadSeal(msgKey, drNonce(msgKey), plaintext, nil)
}

func drMessageOpen(msgKey key32, ciphertext []byte) ([]byte, error) {
	n := drNonce(msgKey)
	return aeadOpen(msgKey, n[:], ciphertext, nil)
}

type drInit struct {
	rk, cks, ckr, ephPub key32
}

func drInitiatorInit(myStatic, theirStatic key32, convID string, eph key32) (drInit, error) {
	rk0, err := drRootKey(myStatic, theirStatic, convID)
	if err != nil {
		return drInit{}, err
	}
	d, err := x25519(eph, theirStatic)
	if err != nil {
		return drInit{}, err
	}
	rk, cks := drKDFRK(rk0, d)
	return drInit{rk: rk, cks: cks, ephPub: x25519Pub(eph)}, nil
}

func drResponderInit(myStatic, theirStatic key32, convID string, incomingDHR, eph key32) (drInit, error) {
	rk0, err := drRootKey(myStatic, theirStatic, convID)
	if err != nil {
		return drInit{}, err
	}
	d1, err := x25519(myStatic, incomingDHR)
	if err != nil {
		return drInit{}, err
	}
	rk1, ckr := drKDFRK(rk0, d1)
	d2, err := x25519(eph, incomingDHR)
	if err != nil {
		return drInit{}, err
	}
	rk, cks := drKDFRK(rk1, d2)
	return drInit{rk: rk, cks: cks, ckr: ckr, ephPub: x25519Pub(eph)}, nil
}

// ---- group sender-key ratchet ----

func be32(v uint32) []byte { return binary.BigEndian.AppendUint32(nil, v) }

func groupMsgKey(chain key32, iteration uint32) key32 {
	return hkdf32(chain[:], be32(iteration), "wavvon/group-msg/v1")
}

func groupNextChainKey(chain key32, iteration uint32) key32 {
	return hkdf32(chain[:], be32(iteration), "wavvon/group-chain/v1")
}

func groupNonce(iteration uint32) [12]byte {
	var n [12]byte
	binary.BigEndian.PutUint32(n[8:], iteration)
	return n
}

// groupMessageSeal returns the ciphertext, the nonce and the chain key for
// iteration+1; the caller stores that before reusing the chain.
func groupMessageSeal(chain key32, iteration uint32, plaintext []byte) ([]byte, [12]byte, key32) {
	n := groupNonce(iteration)
	return aeadSeal(groupMsgKey(chain, iteration), n, plaintext, nil), n, groupNextChainKey(chain, iteration)
}

func groupMessageOpen(chain key32, held, iteration uint32, nonce, ciphertext []byte) ([]byte, error) {
	if iteration < held {
		return nil, dmErr(ErrDMChainAdvanced, "")
	}
	ck := chain
	for i := held; i < iteration; i++ {
		ck = groupNextChainKey(ck, i)
	}
	return aeadOpen(groupMsgKey(ck, iteration), nonce, ciphertext, nil)
}

func groupWrapKey(mySecret, peerPub key32, convID string) (key32, error) {
	shared, err := x25519(mySecret, peerPub)
	if err != nil {
		return key32{}, err
	}
	return hkdf32(shared[:], []byte(convID), "wavvon/group-key-dist/v1"), nil
}

func groupKeyWrap(mySecret, recipientPub key32, convID string, chain key32, iteration uint32, nonce [12]byte) ([]byte, error) {
	k, err := groupWrapKey(mySecret, recipientPub, convID)
	if err != nil {
		return nil, err
	}
	return aeadSeal(k, nonce, append(chain[:], be32(iteration)...), nil), nil
}

func groupKeyUnwrap(mySecret, senderPub key32, convID string, nonce, wrapped []byte) (key32, uint32, error) {
	k, err := groupWrapKey(mySecret, senderPub, convID)
	if err != nil {
		return key32{}, 0, err
	}
	plain, err := aeadOpen(k, nonce, wrapped, nil)
	if err != nil {
		return key32{}, 0, err
	}
	if len(plain) < 36 {
		return key32{}, 0, errors.New("bad wrapped chain key")
	}
	return key32(plain[:32]), binary.BigEndian.Uint32(plain[32:36]), nil
}

// ---- voice ----

func voiceWrapKey(mySecret, peerPub key32, channelID string) (key32, error) {
	shared, err := x25519(mySecret, peerPub)
	if err != nil {
		return key32{}, err
	}
	return hkdf32(shared[:], []byte(channelID), "wavvon/voice-key/v1"), nil
}

const voiceHeaderLen = 16

func voiceKeyWrapWithNonce(seed []byte, recipientPub key32, channelID string, senderKey key32, salt [4]byte, keyID uint32, nonce [12]byte) ([]byte, error) {
	k, err := voiceWrapKey(dhSecretFromSeed(seed), recipientPub, channelID)
	if err != nil {
		return nil, err
	}
	plain := make([]byte, 0, 40)
	plain = append(plain, senderKey[:]...)
	plain = append(plain, salt[:]...)
	plain = append(plain, be32(keyID)...)
	return aeadSeal(k, nonce, plain, nil), nil
}

// VoiceKeyWrap wraps a voice sender key (key, salt, keyID) for one recipient:
// X25519 between the identity's DH key and recipientDH, HKDF with the channel
// id as salt, AES-256-GCM under a fresh random nonce. It returns the
// ciphertext and the nonce.
func VoiceKeyWrap(id *Identity, recipientDH [32]byte, channelID string, senderKey [32]byte, salt [4]byte, keyID uint32) (ciphertext []byte, nonce [12]byte, err error) {
	if _, err = io.ReadFull(rand.Reader, nonce[:]); err != nil {
		return nil, nonce, err
	}
	ciphertext, err = voiceKeyWrapWithNonce(id.key.Seed(), recipientDH, channelID, senderKey, salt, keyID, nonce)
	return ciphertext, nonce, err
}

// VoiceKeyUnwrap is the inverse of VoiceKeyWrap, from the sender's DH key.
func VoiceKeyUnwrap(id *Identity, senderDH [32]byte, channelID string, ciphertext, nonce []byte) (senderKey [32]byte, salt [4]byte, keyID uint32, err error) {
	k, err := voiceWrapKey(dhSecretFromSeed(id.key.Seed()), senderDH, channelID)
	if err != nil {
		return
	}
	plain, err := aeadOpen(k, nonce, ciphertext, nil)
	if err != nil {
		return
	}
	if len(plain) != 40 {
		err = errors.New("wrapped voice key must be 40 bytes")
		return
	}
	copy(senderKey[:], plain[:32])
	copy(salt[:], plain[32:36])
	keyID = binary.BigEndian.Uint32(plain[36:])
	return
}

func voiceNonce(salt [4]byte, ctr uint64) [12]byte {
	var n [12]byte
	copy(n[:4], salt[:])
	binary.BigEndian.PutUint64(n[4:], ctr)
	return n
}

// VoicePacketSeal seals an uplink voice datagram: the cleartext header
// key_id(4) || ctr(8) || ts(4), big-endian, which is also the AEAD's
// associated data, then the ciphertext of the Opus packet.
func VoicePacketSeal(senderKey [32]byte, salt [4]byte, keyID uint32, ctr uint64, ts uint32, opus []byte) []byte {
	header := make([]byte, 0, voiceHeaderLen)
	header = binary.BigEndian.AppendUint32(header, keyID)
	header = binary.BigEndian.AppendUint64(header, ctr)
	header = binary.BigEndian.AppendUint32(header, ts)
	return append(header, aeadSeal(senderKey, voiceNonce(salt, ctr), opus, header)...)
}

// VoicePacketOpen opens a sealed voice datagram and returns its header fields
// and the Opus packet.
func VoicePacketOpen(senderKey [32]byte, salt [4]byte, packet []byte) (keyID uint32, ctr uint64, ts uint32, opus []byte, err error) {
	if len(packet) < voiceHeaderLen+16 {
		err = errors.New("voice packet too short")
		return
	}
	header := packet[:voiceHeaderLen]
	keyID = binary.BigEndian.Uint32(header[0:4])
	ctr = binary.BigEndian.Uint64(header[4:12])
	ts = binary.BigEndian.Uint32(header[12:16])
	n := voiceNonce(salt, ctr)
	opus, err = aeadOpen(senderKey, n[:], packet[voiceHeaderLen:], header)
	return
}
