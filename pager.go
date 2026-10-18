package wavvon

import (
	"context"
	"iter"
)

// MaxPageSize is what the hub clamps limit to; asking for more would look like
// a short page and end the walk early.
const MaxPageSize = 500

// Paginate walks a keyset-paged list to exhaustion. The hub's dialect is a
// bare array plus limit and cursor, where the cursor is the key of the
// previous page's last row (code for invites, public_key for users, id for
// most others), so key extracts it. A page shorter than limit is the end; one
// page is not the list.
//
// fetchPage makes the request (cursor is "" for the first page) and must
// return an error on failure: an error never reads as an empty page, and it
// is yielded as the last pair. Check the endpoint's capability (list.cursor
// or list.cursor.lists) first; a hub without it ignores the cursor, which
// this detects and reports as ErrCursorIgnored rather than looping.
func Paginate[T any](ctx context.Context, fetchPage func(ctx context.Context, cursor string, limit int) ([]T, error), key func(T) string, limit int) iter.Seq2[T, error] {
	size := min(max(1, limit), MaxPageSize)
	return func(yield func(T, error) bool) {
		var zero T
		cursor, previousFirst := "", ""
		for {
			page, err := fetchPage(ctx, cursor, size)
			if err != nil {
				yield(zero, err)
				return
			}
			if len(page) > 0 && cursor != "" && key(page[0]) == previousFirst {
				yield(zero, ErrCursorIgnored)
				return
			}
			for _, item := range page {
				if !yield(item, nil) {
					return
				}
			}
			if len(page) < size {
				return
			}
			previousFirst, cursor = key(page[0]), key(page[len(page)-1])
		}
	}
}
