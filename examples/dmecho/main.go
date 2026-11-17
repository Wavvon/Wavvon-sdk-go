// Command dmecho is an echo program over end-to-end encrypted DMs: whoever
// writes to it gets their own text back, encrypted. It shows the three things
// a DM program does: publish its DH key, learn of new messages from dm
// events, read them with Poll.
//
//	WAVVON_HUB=http://localhost:3000 WAVVON_SEED=<64 hex> [WAVVON_INVITE=code] go run ./examples/dmecho
package main

import (
	"context"
	"errors"
	"log"
	"os"
	"os/signal"

	wavvon "github.com/Wavvon/Wavvon-sdk-go"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	id, err := wavvon.IdentityFromHexSeed(os.Getenv("WAVVON_SEED"))
	if err != nil {
		log.Fatal(err)
	}
	client, err := wavvon.NewClient(wavvon.ClientOptions{
		HubURL: os.Getenv("WAVVON_HUB"), Identity: id, InviteCode: os.Getenv("WAVVON_INVITE"),
	})
	if err != nil {
		log.Fatal(err)
	}
	// Without a published key nobody can encrypt to this program.
	if _, err := client.PublishDHKey(ctx); err != nil {
		log.Fatal(err)
	}
	dms := client.DMs()
	log.Println("echoing DMs as", id.PublicKey)

	// Start from now: whatever is already there is not echoed.
	convs, err := dms.Conversations(ctx)
	if err != nil {
		log.Fatal(err)
	}
	for _, c := range convs {
		if err := dms.SkipExisting(ctx, c.ID); err != nil {
			log.Fatal(err)
		}
	}

	events := client.Connect(wavvon.EventStreamOptions{})
	defer events.Close()
	for {
		ev, err := events.Next(ctx)
		if err != nil {
			if !errors.Is(err, context.Canceled) {
				log.Println(err)
			}
			return
		}
		dm, ok := ev.(*wavvon.DMEvent)
		if !ok {
			if _, err := dms.HandleEvent(ctx, ev); err != nil {
				log.Println("rotating a group key:", err)
			}
			continue
		}
		msgs, err := dms.Poll(ctx, dm.ConversationID)
		if err != nil {
			log.Println("reading", dm.ConversationID, err)
			continue
		}
		for _, m := range msgs {
			if m.Sender == id.PublicKey {
				continue
			}
			if m.Err != nil {
				log.Printf("cannot read %s: %v", m.ID, m.Err)
				continue
			}
			if _, err := dms.SendText(ctx, dm.ConversationID, "echo: "+m.Content.Content); err != nil {
				log.Println("echoing:", err)
			}
		}
	}
}
