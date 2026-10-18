// Command echobot echoes every message in the channels it can read and
// answers /echo.
//
//	WAVVON_HUB=https://hub.example  WAVVON_SEED=<64 hex chars> \
//	WAVVON_INVITE=<code, first run only>  WAVVON_WEBHOOK_URL=https://bot.example/hook \
//	PORT=8080 go run ./examples/echobot
//
// The identity needs a role carrying apps.register to register /echo. The
// hub POSTs invocations to WAVVON_WEBHOOK_URL, which must reach PORT here.
package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"

	wavvon "github.com/Wavvon/Wavvon-sdk-go"
	"github.com/Wavvon/Wavvon-sdk-go/rest"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	id, err := wavvon.IdentityFromHexSeed(os.Getenv("WAVVON_SEED"))
	if err != nil {
		log.Fatal(err)
	}
	client, err := wavvon.NewClient(wavvon.ClientOptions{
		HubURL:     os.Getenv("WAVVON_HUB"),
		Identity:   id,
		InviteCode: os.Getenv("WAVVON_INVITE"),
	})
	if err != nil {
		log.Fatal(err)
	}
	session, err := client.Login(ctx)
	if err != nil {
		log.Fatal(err)
	}
	info, err := client.Info(ctx, false)
	if err != nil {
		log.Fatal(err)
	}

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	go func() {
		log.Fatal(http.ListenAndServe(":"+port, &wavvon.DispatchHandler{
			HubPublicKey: info.PublicKey,
			OnSlashCommand: func(_ context.Context, inv *wavvon.SlashInvocation) (*wavvon.AppResponse, error) {
				body := inv.ArgsRaw
				if body == "" {
					body = "(nothing to echo)"
				}
				return &wavvon.AppResponse{Reply: &wavvon.Reply{Body: body}, Ephemeral: true}, nil
			},
		}))
	}()

	webhook := os.Getenv("WAVVON_WEBHOOK_URL")
	if err := client.SetAppProfile(ctx, wavvon.AppProfile{Name: "Echo", WebhookUrl: &webhook}); err != nil {
		log.Fatal(err)
	}
	if err := client.SetAppCommands(ctx, []wavvon.AppCommand{{Name: "echo", Description: "Repeat what you say, to you only", Args: "<text>"}}); err != nil {
		log.Fatal(err)
	}

	// Connect after SetAppProfile, so the hub treats the socket as an app's.
	events := client.Connect(wavvon.EventStreamOptions{})
	defer events.Close()
	events.OnStateChange(func(s wavvon.ConnectionState) { log.Printf("socket: %s", s) })
	for {
		ev, err := events.Next(ctx)
		if err != nil {
			return
		}
		switch e := ev.(type) {
		case *wavvon.UnknownEvent:
			log.Printf("unmodelled frame: %s", e.RawType)
		case *wavvon.MessageEvent:
			m := e.Message
			if e.Type != "message" || m.Content == nil || m.Sender == nil || *m.Sender == session.CanonicalPubkey || m.VisibleToPubkey != nil || strings.HasPrefix(*m.Content, "/") {
				continue
			}
			if _, err := wavvon.Check(client.Rest.CreateChannelMessageWithResponse(ctx, e.ChannelID, rest.CreateChannelMessageJSONRequestBody{Content: "echo: " + *m.Content})); err != nil {
				log.Printf("echo failed: %v", err)
			}
		}
	}
}
