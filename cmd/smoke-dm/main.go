// Command smoke-dm exercises E2E DMs against a real hub with fresh identities:
// a 1:1 double ratchet (round trip, reply, ratchet step, history re-read), a
// refused send to a peer with no DH key, a group with sender keys and a
// rotation, and an explicit plaintext DM.
//
//	WAVVON_SMOKE_HUB=http://localhost:3000 [WAVVON_SMOKE_SEED=<64 hex>] go run ./cmd/smoke-dm
//
// The seed identity (default 5a repeated) must be a hub owner: start the hub
// with WAVVON_OWNER_PUBKEY set to its public key.
package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"slices"
	"time"

	wavvon "github.com/Wavvon/Wavvon-sdk-go"
	"github.com/Wavvon/Wavvon-sdk-go/internal/smokeutil"
)

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	if err := run(ctx); err != nil {
		fmt.Fprintln(os.Stderr, "DM SMOKE FAILED:", err)
		os.Exit(1)
	}
	fmt.Println("DM SMOKE OK")
}

func texts(msgs []wavvon.DMMessage, from string) ([]string, error) {
	var out []string
	for _, m := range msgs {
		if from != "" && m.Sender != from {
			continue
		}
		if m.Err != nil {
			return nil, fmt.Errorf("message %s unreadable: %w", m.ID, m.Err)
		}
		out = append(out, m.Content.Content)
	}
	return out, nil
}

func expect(what string, got []string, want ...string) error {
	if !slices.Equal(got, want) {
		return fmt.Errorf("%s: got %q, want %q", what, got, want)
	}
	return nil
}

func run(ctx context.Context) error {
	hub, err := smokeutil.Hub()
	if err != nil {
		return err
	}
	owner, err := smokeutil.Owner(ctx, hub)
	if err != nil {
		return err
	}
	var clients [3]*wavvon.Client
	for i := range clients {
		if clients[i], err = smokeutil.Join(ctx, hub, owner); err != nil {
			return err
		}
	}
	a, b, c := clients[0], clients[1], clients[2]
	fmt.Println("joined A", a.Identity.PublicKey[:8], "B", b.Identity.PublicKey[:8], "C", c.Identity.PublicKey[:8])

	for _, cl := range []*wavvon.Client{a, b} {
		if _, err := cl.PublishDHKey(ctx); err != nil {
			return err
		}
	}
	if again, err := b.PublishDHKey(ctx); err != nil || again {
		return fmt.Errorf("a second publish must be a no-op: %v, %v", again, err)
	}
	da, db := a.DMs(), b.DMs()

	// C has published no key: encrypting to it is refused, never downgraded.
	toC, err := da.CreateConversation(ctx, []string{c.Identity.PublicKey})
	if err != nil {
		return err
	}
	var noKey *wavvon.RecipientHasNoKeyError
	if _, err := da.SendText(ctx, toC.ID, "secret"); !errors.As(err, &noKey) {
		return fmt.Errorf("expected RecipientHasNoKeyError, got %v", err)
	}
	if left, err := da.Messages(ctx, toC.ID, wavvon.MessagesPage{}); err != nil || len(left) != 0 {
		return fmt.Errorf("a refused send left %d messages (%v)", len(left), err)
	}
	fmt.Println("no DH key: refused, nothing sent")

	conv, err := da.CreateConversation(ctx, []string{b.Identity.PublicKey})
	if err != nil {
		return err
	}
	if _, err := da.SendText(ctx, conv.ID, "hello B"); err != nil {
		return err
	}
	if _, err := da.SendText(ctx, conv.ID, "second"); err != nil {
		return err
	}
	got, err := db.Poll(ctx, conv.ID)
	if err != nil {
		return err
	}
	if t, err := texts(got, ""); err != nil {
		return err
	} else if err := expect("B reads A", t, "hello B", "second"); err != nil {
		return err
	}
	for _, m := range got {
		if !m.Encrypted {
			return errors.New("a DM arrived in the clear")
		}
	}
	if _, err := db.SendText(ctx, conv.ID, "hi A"); err != nil {
		return err
	}
	if got, err = da.Poll(ctx, conv.ID); err != nil {
		return err
	}
	if t, err := texts(got, b.Identity.PublicKey); err != nil {
		return err
	} else if err := expect("A reads B", t, "hi A"); err != nil {
		return err
	}
	if _, err := da.SendText(ctx, conv.ID, "third, after the reply"); err != nil {
		return err
	}
	if got, err = db.Poll(ctx, conv.ID); err != nil {
		return err
	}
	if t, err := texts(got, a.Identity.PublicKey); err != nil {
		return err
	} else if err := expect("B reads A after the ratchet step", t, "third, after the reply"); err != nil {
		return err
	}
	again, err := db.Messages(ctx, conv.ID, wavvon.MessagesPage{})
	if err != nil {
		return err
	}
	readable := 0
	for _, m := range again {
		if m.Err == nil {
			readable++
		}
	}
	if readable < 3 {
		return fmt.Errorf("history re-read lost messages: %d readable", readable)
	}
	fmt.Println("1:1 double ratchet: round trip, reply, ratchet step, re-read")

	if _, err := c.PublishDHKey(ctx); err != nil {
		return err
	}
	group, err := da.CreateConversation(ctx, []string{b.Identity.PublicKey, c.Identity.PublicKey})
	if err != nil {
		return err
	}
	sent, err := da.SendText(ctx, group.ID, "hello group")
	if err != nil {
		return err
	}
	if sent.Distribution == nil || len(sent.Distribution.Delivered) != 2 {
		return fmt.Errorf("first group send must distribute to both: %+v", sent.Distribution)
	}
	for _, m := range []*wavvon.Client{b, c} {
		got, err := m.DMs().Poll(ctx, group.ID)
		if err != nil {
			return err
		}
		t, err := texts(got, "")
		if err != nil {
			return err
		}
		if err := expect("group member reads", t, "hello group"); err != nil {
			return err
		}
	}
	if _, err := da.RotateGroupKey(ctx, group.ID); err != nil {
		return err
	}
	if _, err := da.SendText(ctx, group.ID, "after rotation"); err != nil {
		return err
	}
	if got, err = c.DMs().Poll(ctx, group.ID); err != nil {
		return err
	}
	t, err := texts(got, "")
	if err != nil {
		return err
	}
	if err := expect("C reads after rotation", t, "after rotation"); err != nil {
		return err
	}
	fmt.Println("group sender keys: distribute, read, rotate, read")

	clear, err := da.SendPlaintext(ctx, conv.ID, "explicit plaintext")
	if err != nil {
		return err
	}
	rows, err := db.Messages(ctx, conv.ID, wavvon.MessagesPage{})
	if err != nil {
		return err
	}
	for _, m := range rows {
		if m.ID == clear.ID {
			if m.Encrypted || m.Err != nil || m.Content.Content != "explicit plaintext" {
				return fmt.Errorf("plaintext row: %+v", m)
			}
			return nil
		}
	}
	return errors.New("the plaintext row is missing")
}
