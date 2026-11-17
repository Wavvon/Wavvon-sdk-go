// Package smokeutil is what the DM and voice smoke commands share: the hub
// owner and fresh identities admitted by invites the owner mints.
package smokeutil

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"strings"

	wavvon "github.com/Wavvon/Wavvon-sdk-go"
	"github.com/Wavvon/Wavvon-sdk-go/rest"
)

// Hub is the hub the smoke runs against (WAVVON_SMOKE_HUB).
func Hub() (string, error) {
	hub := os.Getenv("WAVVON_SMOKE_HUB")
	if hub == "" {
		return "", errors.New("set WAVVON_SMOKE_HUB")
	}
	return hub, nil
}

// Owner connects as the hub owner, whose seed is WAVVON_SMOKE_SEED (64 hex,
// default 5a repeated). Start the hub with WAVVON_OWNER_PUBKEY set to its
// public key so it can mint the invites the others join with.
func Owner(ctx context.Context, hub string) (*wavvon.Client, error) {
	seed := os.Getenv("WAVVON_SMOKE_SEED")
	if seed == "" {
		seed = strings.Repeat("5a", 32)
	}
	id, err := wavvon.IdentityFromHexSeed(seed)
	if err != nil {
		return nil, err
	}
	c, err := wavvon.NewClient(wavvon.ClientOptions{HubURL: hub, Identity: id})
	if err != nil {
		return nil, err
	}
	_, err = c.Login(ctx)
	return c, err
}

// Join admits a fresh identity with an invite bound to its key.
func Join(ctx context.Context, hub string, owner *wavvon.Client) (*wavvon.Client, error) {
	seed := make([]byte, 32)
	if _, err := rand.Read(seed); err != nil {
		return nil, err
	}
	id, err := wavvon.IdentityFromSeed(seed)
	if err != nil {
		return nil, err
	}
	pub := id.PublicKey
	inv, err := wavvon.Check(owner.Rest.CreateInviteWithResponse(ctx, rest.CreateInviteJSONRequestBody{BoundPubkey: &pub}))
	if err != nil || inv.JSON201 == nil || inv.JSON201.Code == nil {
		return nil, fmt.Errorf("create invite: %v", err)
	}
	c, err := wavvon.NewClient(wavvon.ClientOptions{HubURL: hub, Identity: id, InviteCode: *inv.JSON201.Code})
	if err != nil {
		return nil, err
	}
	_, err = c.Login(ctx)
	return c, err
}

// VoiceChannel creates a fresh voice channel as the owner and returns its id.
func VoiceChannel(ctx context.Context, owner *wavvon.Client) (string, error) {
	var b [3]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	typ := "voice"
	res, err := wavvon.Check(owner.Rest.CreateChannelWithResponse(ctx, rest.CreateChannelJSONRequestBody{
		Name: fmt.Sprintf("voice-smoke-%x", b), ChannelType: &typ,
	}))
	if err != nil || res.JSON201 == nil || res.JSON201.Id == nil {
		return "", fmt.Errorf("create voice channel: %v", err)
	}
	return *res.JSON201.Id, nil
}
