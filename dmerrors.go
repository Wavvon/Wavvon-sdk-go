package wavvon

import (
	"errors"
	"fmt"
)

// RecipientHasNoKeyError means a peer has published no DH key on this hub, so
// nothing can be encrypted or wrapped to it. Never sent in the clear instead.
type RecipientHasNoKeyError struct{ PublicKey string }

func (e *RecipientHasNoKeyError) Error() string {
	return fmt.Sprintf("wavvon: %s has published no DH key on this hub", e.PublicKey)
}

// DHKeyChangedError means a peer's DH key differs from the one pinned on first
// use. Nothing is encrypted to it until the program calls AcceptDHKey.
type DHKeyChangedError struct {
	PublicKey string
	Pinned    string
	Fetched   string
}

func (e *DHKeyChangedError) Error() string {
	return fmt.Sprintf("wavvon: DH key of %s changed (pinned %s, hub now has %s)", e.PublicKey, e.Pinned, e.Fetched)
}

// DHKeyUnsignedError means the hub holds a DH record for PublicKey that
// PublicKey did not sign. The hub is not trusted with it.
type DHKeyUnsignedError struct{ PublicKey string }

func (e *DHKeyUnsignedError) Error() string {
	return fmt.Sprintf("wavvon: DH key record for %s is not signed by its owner", e.PublicKey)
}

// DMError is why one DM could not be read or sent. It is per message: a
// program keeps going. Match the reason with errors.Is against the ErrDM*
// values below.
type DMError struct {
	// Reason is one of the ErrDM* values.
	Reason error
	// Detail adds what Reason does not say.
	Detail string
}

func (e *DMError) Error() string {
	if e.Detail != "" {
		return e.Reason.Error() + ": " + e.Detail
	}
	return e.Reason.Error()
}

// Unwrap makes errors.Is(err, ErrDM...) work.
func (e *DMError) Unwrap() error { return e.Reason }

// Reasons carried by DMError.
var (
	// ErrDMNotSignedBySender: the envelope is not signed by the member the hub
	// names as its sender, directly or through a cert that member issued. It
	// is not decrypted.
	ErrDMNotSignedBySender = errors.New("wavvon: envelope is not signed by its sender")
	// ErrDMOwnMessage: a ratchet cannot read what it sent itself. Keeping a
	// copy is the program's business.
	ErrDMOwnMessage = errors.New("wavvon: this program sent the message; a ratchet cannot decrypt its own output")
	// ErrDMMalformed: the envelope or its plaintext is not in the expected shape.
	ErrDMMalformed = errors.New("wavvon: malformed envelope")
	// ErrDMDecryptionFailed: the AEAD did not open.
	ErrDMDecryptionFailed = errors.New("wavvon: decryption failed")
	// ErrDMNoSession: there is no ratchet session for the conversation.
	ErrDMNoSession = errors.New("wavvon: no ratchet session for this conversation")
	// ErrDMTooManySkipped: more than 1000 skipped messages.
	ErrDMTooManySkipped = errors.New("wavvon: more than 1000 skipped messages")
	// ErrDMKeyNotFound: no sender key from that member at that version.
	ErrDMKeyNotFound = errors.New("wavvon: no sender key from that member at that version")
	// ErrDMChainAdvanced: the sender's chain was already advanced past this message.
	ErrDMChainAdvanced = errors.New("wavvon: the sender's chain was already advanced past this message")
)

func dmErr(reason error, detail string) *DMError { return &DMError{Reason: reason, Detail: detail} }

// perMessage reports whether err belongs to one message or peer rather than to
// the call that met it.
func perMessage(err error) bool {
	var (
		dm      *DMError
		noKey   *RecipientHasNoKeyError
		changed *DHKeyChangedError
		unsign  *DHKeyUnsignedError
	)
	return errors.As(err, &dm) || errors.As(err, &noKey) || errors.As(err, &changed) || errors.As(err, &unsign)
}
