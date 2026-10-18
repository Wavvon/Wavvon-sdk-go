package wavvon

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"testing"
)

type row struct{ Code string }

var rows = func() []row {
	out := make([]row, 7)
	for i := range out {
		out[i] = row{fmt.Sprintf("c%d", i)}
	}
	return out
}()

// endpoint behaves like a hub keyset list: rows after the cursor, at most limit.
func endpoint(_ context.Context, cursor string, limit int) ([]row, error) {
	from := 0
	if cursor != "" {
		from = slices.IndexFunc(rows, func(r row) bool { return r.Code == cursor }) + 1
	}
	return rows[from:min(from+limit, len(rows))], nil
}

func code(r row) string { return r.Code }

func collect(t *testing.T, fetch func(context.Context, string, int) ([]row, error), limit int) ([]row, error) {
	t.Helper()
	var out []row
	for r, err := range Paginate(context.Background(), fetch, code, limit) {
		if err != nil {
			return out, err
		}
		out = append(out, r)
	}
	return out, nil
}

func TestPaginateWalksEveryPage(t *testing.T) {
	got, err := collect(t, endpoint, 3)
	if err != nil || !slices.Equal(got, rows) {
		t.Fatalf("got %v, %v", got, err)
	}
}

func TestPaginateStopsAfterAnEmptyPageOnAnExactlyFullLastPage(t *testing.T) {
	var cursors []string
	got, err := collect(t, func(ctx context.Context, c string, l int) ([]row, error) {
		cursors = append(cursors, c)
		return endpoint(ctx, c, l)
	}, 7)
	if err != nil || !slices.Equal(got, rows) || !slices.Equal(cursors, []string{"", "c6"}) {
		t.Fatalf("got %v, %v, cursors %q", got, err, cursors)
	}
}

func TestPaginateClampsThePageSize(t *testing.T) {
	var limits []int
	_, _ = collect(t, func(ctx context.Context, c string, l int) ([]row, error) {
		limits = append(limits, l)
		return endpoint(ctx, c, l)
	}, 10_000)
	if limits[0] != MaxPageSize {
		t.Fatalf("first limit %d", limits[0])
	}
}

func TestPaginateRefusesToLoopOnAnIgnoredCursor(t *testing.T) {
	_, err := collect(t, func(_ context.Context, _ string, l int) ([]row, error) { return rows[:l], nil }, 3)
	if !errors.Is(err, ErrCursorIgnored) {
		t.Fatalf("got %v", err)
	}
}

func TestPaginatePropagatesAFailedPage(t *testing.T) {
	boom := errors.New("503")
	got, err := collect(t, func(ctx context.Context, c string, l int) ([]row, error) {
		if c != "" {
			return nil, boom
		}
		return endpoint(ctx, c, l)
	}, 3)
	if !errors.Is(err, boom) || len(got) != 3 {
		t.Fatalf("got %v, %v", got, err)
	}
}
