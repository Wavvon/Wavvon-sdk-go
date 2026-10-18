package wavvon

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

func noSleep() RetryOptions {
	return RetryOptions{
		sleep:  func(context.Context, time.Duration) error { return nil },
		random: func() float64 { return 1 },
	}
}

func status(code int) *http.Response {
	return &http.Response{StatusCode: code, Body: io.NopCloser(strings.NewReader(""))}
}

func TestTransientStatuses(t *testing.T) {
	for _, s := range []int{429, 500, 502, 503} {
		if !IsTransientStatus(s) {
			t.Errorf("%d should be transient", s)
		}
	}
	for _, s := range []int{200, 400, 401, 403, 404} {
		if IsTransientStatus(s) {
			t.Errorf("%d should be an answer", s)
		}
	}
}

func TestBackoffIsCappedExponential(t *testing.T) {
	o := RetryOptions{BaseDelay: 100 * time.Millisecond, MaxDelay: time.Second, random: func() float64 { return 1 }}
	want := map[int]time.Duration{1: 100, 2: 200, 3: 400, 4: 800, 5: 1000, 9: 1000, 80: 1000}
	for n, ms := range want {
		if got := o.Backoff(n); got != ms*time.Millisecond {
			t.Errorf("Backoff(%d) = %v, want %v", n, got, ms*time.Millisecond)
		}
	}
	o.random = func() float64 { return 0 }
	if o.Backoff(3) != 0 {
		t.Error("full jitter must reach 0")
	}
}

func TestRetriesUntilAnAnswer(t *testing.T) {
	statuses := []int{429, 503, 200}
	var seen []int
	o := noSleep()
	o.OnRetry = func(i RetryInfo) { seen = append(seen, i.Status) }
	res, err := DoWithRetry(context.Background(), o, func(context.Context) (*http.Response, error) {
		s := statuses[0]
		statuses = statuses[1:]
		return status(s), nil
	})
	if err != nil || res.StatusCode != 200 {
		t.Fatalf("got %v, %v", res, err)
	}
	if len(seen) != 2 || seen[0] != 429 || seen[1] != 503 {
		t.Errorf("OnRetry saw %v", seen)
	}
}

func TestRetriesNetworkErrors(t *testing.T) {
	n := 0
	res, err := DoWithRetry(context.Background(), noSleep(), func(context.Context) (*http.Response, error) {
		if n++; n < 3 {
			return nil, errors.New("connection refused")
		}
		return status(200), nil
	})
	if err != nil || res.StatusCode != 200 {
		t.Fatalf("got %v, %v", res, err)
	}
}

func TestNeverReturnsATransientFailureAsTheAnswer(t *testing.T) {
	o := noSleep()
	o.MaxAttempts = 3
	_, err := DoWithRetry(context.Background(), o, func(context.Context) (*http.Response, error) { return status(429), nil })
	var hu *HubUnavailableError
	if !errors.As(err, &hu) || hu.LastStatus != 429 || hu.Attempts != 3 {
		t.Fatalf("want HubUnavailableError{429, 3}, got %v", err)
	}
}

func TestReturnsADefinitiveRefusalWithoutRetrying(t *testing.T) {
	calls := 0
	res, err := DoWithRetry(context.Background(), noSleep(), func(context.Context) (*http.Response, error) {
		calls++
		return status(403), nil
	})
	if err != nil || res.StatusCode != 403 || calls != 1 {
		t.Fatalf("got %v, %v after %d calls", res, err, calls)
	}
}
