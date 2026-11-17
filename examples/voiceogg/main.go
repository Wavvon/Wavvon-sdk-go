// Command voiceogg plays an Ogg Opus file into a voice channel. The packets
// are demuxed and passed through as they are: no codec, no native library.
// Each must be a single 20 ms frame (opusenc --framesize 20, its default); the
// SDK refuses anything else, because desktop listeners could not play it.
//
//	WAVVON_HUB=http://localhost:3000 WAVVON_SEED=<64 hex> [WAVVON_INVITE=code] \
//	go run ./examples/voiceogg <channel id> <file.opus>
//
// Only play what may be redistributed: public domain, CC0, or a Creative
// Commons licence that allows it. The SDK carries audio and judges none of it.
package main

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"os"

	wavvon "github.com/Wavvon/Wavvon-sdk-go"
	"github.com/Wavvon/Wavvon-sdk-go/voice"
)

// oggPackets calls fn with every packet of the first logical stream. It reads
// the page framing (RFC 3533) and does not check CRCs.
func oggPackets(r io.Reader, fn func([]byte) error) error {
	br := bufio.NewReader(r)
	var packet []byte
	for {
		var head [27]byte
		if _, err := io.ReadFull(br, head[:]); err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
		if string(head[:4]) != "OggS" {
			return errors.New("not an Ogg file")
		}
		lacing := make([]byte, head[26])
		if _, err := io.ReadFull(br, lacing); err != nil {
			return err
		}
		for _, n := range lacing {
			seg := make([]byte, n)
			if _, err := io.ReadFull(br, seg); err != nil {
				return err
			}
			packet = append(packet, seg...)
			if n < 255 {
				if err := fn(packet); err != nil {
					return err
				}
				packet = nil
			}
		}
	}
}

func main() {
	if len(os.Args) != 3 {
		log.Fatal("usage: voiceogg <channel id> <file.opus>")
	}
	ctx := context.Background()
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
	room, err := voice.Join(ctx, client, os.Args[1])
	if err != nil {
		log.Fatal(err)
	}
	// The room's events must be read or they pile up; this program only
	// reports what goes wrong.
	go func() {
		for ev := range room.Events() {
			if f, ok := ev.(voice.Failure); ok {
				log.Println("voice:", f.Err)
			}
		}
	}()

	f, err := os.Open(os.Args[2])
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()
	sent := 0
	err = oggPackets(f, func(p []byte) error {
		// OpusHead and OpusTags are the first two packets of the stream.
		if bytes.HasPrefix(p, []byte("OpusHead")) || bytes.HasPrefix(p, []byte("OpusTags")) {
			return nil
		}
		// Held to real time by the SDK: reading the file is not the clock.
		if err := room.SendOpus(ctx, p); err != nil {
			return err
		}
		sent++
		return nil
	})
	if err != nil {
		log.Println(err)
	}
	fmt.Printf("sent %d packets (%d s)\n", sent, sent/50)
	if err := room.Leave(ctx); err != nil {
		log.Fatal(err)
	}
}
