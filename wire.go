package wavvon

import (
	"crypto/ed25519"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"sort"
	"strconv"
)

// The signing bytes of the DM and DH-key envelopes (wire-format.md). Each is
// pinned by a vector in Wavvon-server's wire-vectors.json.

type wbuf []byte

func (b *wbuf) u32(v uint32) { *b = binary.LittleEndian.AppendUint32(*b, v) }
func (b *wbuf) u64(v uint64) { *b = binary.LittleEndian.AppendUint64(*b, v) }
func (b *wbuf) str(s string) { b.u32(uint32(len(s))); *b = append(*b, s...) }
func (b *wbuf) strs(v []string) {
	b.u32(uint32(len(v)))
	for _, s := range v {
		b.str(s)
	}
}

func dec(v uint32) string { return strconv.FormatUint(uint64(v), 10) }

// DHKeyRecordSigningBytes is what a public key signs to publish its X25519 key.
func DHKeyRecordSigningBytes(pubkey, dhPubkeyHex string) []byte {
	b := wbuf("wavvon/dh-key/v1\x00")
	b.str(pubkey)
	b.str(dhPubkeyHex)
	return b
}

// DMEnvelopeSigningBytes is the signing input of a v1 1:1 envelope
// (dm-ciphertext/v1). Ciphertext and nonce are their hex strings.
func DMEnvelopeSigningBytes(convID, ciphertextHex, nonceHex, dhPubkeyHex string) []byte {
	b := wbuf("wavvon/dm-ciphertext/v1\x00")
	b.str(convID)
	b.str(ciphertextHex)
	b.str(nonceHex)
	b.str(dhPubkeyHex)
	return b
}

// DREnvelopeSigningBytes is the signing input of a double-ratchet envelope
// (dm-ciphertext/v2).
func DREnvelopeSigningBytes(convID string, messageIndex, prevCount uint32, ciphertextHex, dhPubkeyHex string) []byte {
	b := wbuf("wavvon/dm-ciphertext/v2\x00")
	b.str(convID)
	b.u32(messageIndex)
	b.u32(prevCount)
	b.str(ciphertextHex)
	b.str(dhPubkeyHex)
	return b
}

// GroupDMEnvelopeSigningBytes is the signing input of a group envelope. The
// integers are length-prefixed decimal strings, not raw integers.
func GroupDMEnvelopeSigningBytes(convID string, senderKeyVersion, iteration uint32, ciphertextHex, nonceHex string) []byte {
	b := wbuf("wavvon/group-dm-ciphertext/v1\x00")
	b.str(convID)
	b.str(dec(senderKeyVersion))
	b.str(dec(iteration))
	b.str(ciphertextHex)
	b.str(nonceHex)
	return b
}

// SenderKeyRecipient is one (recipient, wrapped key) pair of a sender-key
// distribution.
type SenderKeyRecipient struct {
	PublicKey     string
	WrappedKeyHex string
}

// SenderKeyDistSigningBytes is the signing input of a sender-key distribution.
// Recipients are sorted by public key, so the order given does not matter.
func SenderKeyDistSigningBytes(convID string, version uint32, recipients []SenderKeyRecipient) []byte {
	sorted := append([]SenderKeyRecipient(nil), recipients...)
	sort.SliceStable(sorted, func(i, j int) bool { return sorted[i].PublicKey < sorted[j].PublicKey })
	b := wbuf("wavvon/group-key-dist/v1\x00")
	b.str(convID)
	b.str(dec(version))
	for _, r := range sorted {
		b.str(r.PublicKey)
		b.str(r.WrappedKeyHex)
	}
	return b
}

// DMMemberChangeSigningBytes is what a group member signs to add members or leave.
func DMMemberChangeSigningBytes(convID, actor string, added, removed []string, issuedAt uint64) []byte {
	b := wbuf("wavvon/dm-member-change/v1\x00")
	b.str(convID)
	b.str(actor)
	b.strs(added)
	b.strs(removed)
	b.u64(issuedAt)
	return b
}

// FederatedPlaintextDMSigningBytes is the v1 signing input of a plaintext DM.
func FederatedPlaintextDMSigningBytes(convID, convType, content string) []byte {
	b := wbuf("wavvon/federated-dm/v1\x00")
	b.str(convID)
	b.str(convType)
	b.str(content)
	return b
}

// FederatedPlaintextDMV2SigningBytes is the v2 signing input of a plaintext
// DM: it also covers the message id, the timestamp and the member set (sorted,
// de-duplicated).
func FederatedPlaintextDMV2SigningBytes(convID, convType, content, messageID string, createdAt uint64, members []string) []byte {
	sorted := append([]string(nil), members...)
	sort.Strings(sorted)
	uniq := sorted[:0]
	for i, m := range sorted {
		if i == 0 || m != sorted[i-1] {
			uniq = append(uniq, m)
		}
	}
	b := wbuf("wavvon/federated-dm/v2\x00")
	b.str(convID)
	b.str(convType)
	b.str(content)
	b.str(messageID)
	b.u64(createdAt)
	b.strs(uniq)
	return b
}

// SubkeyCert is a master key's certificate for a device subkey.
type SubkeyCert struct {
	MasterPubkey string   `json:"master_pubkey"`
	SubkeyPubkey string   `json:"subkey_pubkey"`
	DeviceLabel  string   `json:"device_label"`
	IssuedAt     uint64   `json:"issued_at"`
	NotAfter     *uint64  `json:"not_after"`
	FallbackHubs []string `json:"fallback_hubs"`
	Signature    string   `json:"signature"`
}

// SubkeyCertSigningBytes is the signing input of a SubkeyCert.
func SubkeyCertSigningBytes(master, subkey, label string, issuedAt uint64, notAfter *uint64, fallbackHubs []string) []byte {
	b := wbuf("wavvon/subkey-cert/v1\x00")
	b.str(master)
	b.str(subkey)
	b.str(label)
	b.u64(issuedAt)
	if notAfter != nil {
		b = append(b, 1)
		b.u64(*notAfter)
	} else {
		b = append(b, 0)
	}
	b.strs(fallbackHubs)
	return b
}

// Verify checks that the master key signed the certificate.
func (c *SubkeyCert) Verify() error {
	msg := SubkeyCertSigningBytes(c.MasterPubkey, c.SubkeyPubkey, c.DeviceLabel, c.IssuedAt, c.NotAfter, c.FallbackHubs)
	sig, err := hex.DecodeString(c.Signature)
	if err != nil {
		return errors.New("signature is not hex")
	}
	return verifySig(c.MasterPubkey, msg, sig)
}

func verifySig(pubkeyHex string, msg, sig []byte) error {
	pub, err := hex.DecodeString(pubkeyHex)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return errors.New("public key is not 32 bytes of hex")
	}
	if !ed25519.Verify(pub, msg, sig) {
		return errors.New("signature verification failed")
	}
	return nil
}
