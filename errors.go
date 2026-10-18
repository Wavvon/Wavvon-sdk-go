package wavvon

import (
	"errors"
	"fmt"
)

// ErrUnsupportedByHub matches, via errors.Is, every UnsupportedByHubError.
var ErrUnsupportedByHub = errors.New("wavvon: unsupported by this hub")

// ErrCursorIgnored is returned by Paginate when the hub serves the same page
// twice: the endpoint does not honour the cursor, and looping would never end.
var ErrCursorIgnored = errors.New("wavvon: the hub returned the same page twice: it does not honour the cursor on this endpoint")

// ErrStreamClosed is returned by EventStream.Next and Send after Close.
var ErrStreamClosed = errors.New("wavvon: event stream closed")

// UnsupportedByHubError means the hub does not advertise a capability the
// call needs. It is never the result of a version comparison.
type UnsupportedByHubError struct {
	Capability string
}

func (e *UnsupportedByHubError) Error() string {
	return fmt.Sprintf("wavvon: this hub does not advertise the %q capability", e.Capability)
}

// Unwrap makes errors.Is(err, ErrUnsupportedByHub) true.
func (e *UnsupportedByHubError) Unwrap() error { return ErrUnsupportedByHub }

// HubUnavailableError means the hub could not be reached or kept saying "not
// now" (429, 5xx, timeout, network) until the retry budget ran out. It is not
// an answer: nothing about the resource can be concluded from it.
type HubUnavailableError struct {
	// LastStatus is the last HTTP status seen, or 0 for a network error or timeout.
	LastStatus int
	Attempts   int
	// Err is the last network error, if the last attempt failed with one.
	Err error
}

func (e *HubUnavailableError) Error() string {
	if e.LastStatus != 0 {
		return fmt.Sprintf("wavvon: hub kept answering %d after %d attempts", e.LastStatus, e.Attempts)
	}
	return fmt.Sprintf("wavvon: hub unreachable after %d attempts: %v", e.Attempts, e.Err)
}

func (e *HubUnavailableError) Unwrap() error { return e.Err }

// HubError is a definitive refusal from the hub: a 4xx other than 429.
type HubError struct {
	Status int
	// Body is the hub's own words, usually plain text.
	Body string
}

func (e *HubError) Error() string {
	return fmt.Sprintf("wavvon: hub answered %d: %s", e.Status, e.Body)
}

// AuthSchemeError means a challenge could not be answered safely: an unknown
// scheme, or a raw challenge of the wrong length.
type AuthSchemeError struct {
	Reason string
}

func (e *AuthSchemeError) Error() string { return "wavvon: " + e.Reason }

// WebhookVerificationError means a webhook request failed verification.
// Answer it with 401 and act on nothing in it.
type WebhookVerificationError struct {
	Reason string
}

func (e *WebhookVerificationError) Error() string { return "wavvon: webhook rejected: " + e.Reason }
