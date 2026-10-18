package wavvon

import (
	"context"
	"errors"
	"io"
	"math/rand/v2"
	"net/http"
	"time"
)

// RetryOptions tune the backoff used for every request. The zero value is the
// default policy.
type RetryOptions struct {
	// MaxAttempts before giving up with HubUnavailableError. 0 means 8; a
	// negative value keeps trying until the context ends.
	MaxAttempts int
	// BaseDelay is the first backoff ceiling. Default 500 ms.
	BaseDelay time.Duration
	// MaxDelay caps the backoff ceiling. Default 30 s.
	MaxDelay time.Duration
	// Timeout per attempt; a timeout counts as transient. Default 15 s.
	Timeout time.Duration
	// OnRetry is called before each wait, so a program can show it is retrying.
	OnRetry func(RetryInfo)

	// Test seams.
	sleep  func(context.Context, time.Duration) error
	random func() float64
}

// RetryInfo describes one failed attempt about to be retried.
type RetryInfo struct {
	Attempt int
	Delay   time.Duration
	// Status is the HTTP status, or 0 for a network error or timeout.
	Status int
	Err    error
}

// IsTransientStatus reports whether a status means "not now": 429, or a 5xx
// from the hub or a proxy in front of it.
func IsTransientStatus(status int) bool { return status == 429 || status >= 500 }

// Backoff is the full-jitter delay before retry number attempt (1-based):
// uniform in [0, min(MaxDelay, BaseDelay * 2^(attempt-1))].
func (o RetryOptions) Backoff(attempt int) time.Duration {
	base, max := o.BaseDelay, o.MaxDelay
	if base <= 0 {
		base = 500 * time.Millisecond
	}
	if max <= 0 {
		max = 30 * time.Second
	}
	ceiling := max
	if attempt-1 < 32 {
		if c := base << (attempt - 1); c > 0 && c < max {
			ceiling = c
		}
	}
	random := o.random
	if random == nil {
		random = rand.Float64
	}
	return time.Duration(random() * float64(ceiling))
}

func (o RetryOptions) maxAttempts() int {
	if o.MaxAttempts == 0 {
		return 8
	}
	return o.MaxAttempts
}

func (o RetryOptions) wait(ctx context.Context, d time.Duration) error {
	if o.sleep != nil {
		return o.sleep(ctx, d)
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// DoWithRetry runs attempt until it yields a response that is not transient.
// The hub sends no Retry-After, so the wait is capped exponential backoff with
// jitter. When the budget runs out it returns *HubUnavailableError rather
// than the last 429/5xx: a transient failure is never an answer.
//
// Each attempt gets its own timeout context, which stays alive until the
// returned body is closed. attempt may make several requests (login does)
// and return whichever response decides the outcome.
func DoWithRetry(ctx context.Context, opts RetryOptions, attempt func(context.Context) (*http.Response, error)) (*http.Response, error) {
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = 15 * time.Second
	}
	max := opts.maxAttempts()
	var lastStatus int
	var lastErr error
	n := 1
	for ; ; n++ {
		actx, cancel := context.WithTimeout(ctx, timeout)
		res, err := attempt(actx)
		var p *permanentError
		if errors.As(err, &p) {
			cancel()
			return nil, p.err
		}
		lastStatus, lastErr = 0, err
		if err == nil {
			if !IsTransientStatus(res.StatusCode) {
				res.Body = &cancelOnClose{res.Body, cancel}
				return res, nil
			}
			lastStatus = res.StatusCode
			_, _ = io.Copy(io.Discard, io.LimitReader(res.Body, 64<<10))
			res.Body.Close()
		}
		cancel()
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if max > 0 && n >= max {
			break
		}
		delay := opts.Backoff(n)
		if opts.OnRetry != nil {
			opts.OnRetry(RetryInfo{Attempt: n, Delay: delay, Status: lastStatus, Err: lastErr})
		}
		if err := opts.wait(ctx, delay); err != nil {
			return nil, err
		}
	}
	return nil, &HubUnavailableError{LastStatus: lastStatus, Attempts: n, Err: lastErr}
}

// permanentError stops DoWithRetry at once: the attempt failed in a way no
// retry can change (a challenge this SDK refuses to sign).
type permanentError struct{ err error }

func (p *permanentError) Error() string { return p.err.Error() }

type cancelOnClose struct {
	io.ReadCloser
	cancel context.CancelFunc
}

func (c *cancelOnClose) Close() error {
	err := c.ReadCloser.Close()
	c.cancel()
	return err
}
