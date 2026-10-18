// Command smoke runs the SDK against a real hub: it authenticates as a fresh
// identity, registers a slash command, posts a message and sees it come back
// over the socket, invokes the command, and checks that the verified
// invocation's reply lands in the channel.
//
// With WAVVON_SMOKE_HUB set it uses that hub:
//
//	WAVVON_SMOKE_HUB      hub URL, e.g. http://localhost:3600
//	WAVVON_SMOKE_INVITE   an invite whose role grants apps.register
//	WAVVON_SMOKE_CHANNEL  optional channel id; default the first text channel
//
// Without it, it boots a hub binary on a fresh database and sets it up as its
// owner first (a role carrying apps.register, an invite granting it, a
// channel), then drops the database:
//
//	WAVVON_HUB_BIN       default ../../server/target/debug/wavvon-hub[.exe]
//	WAVVON_PG            PostgreSQL base URL (default postgres://postgres:postgres@localhost:5432)
//	WAVVON_PG_CONTAINER  docker container used to create the database (default wavvon-pg)
//
// WAVVON_SMOKE_WEBHOOK_HOST is the host the hub reaches this process at
// (default localhost).
package main

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"time"

	wavvon "github.com/Wavvon/Wavvon-sdk-go"
	"github.com/Wavvon/Wavvon-sdk-go/rest"
)

const smokeDB = "wavvon_sdk_go_smoke"

func step(format string, a ...any) { fmt.Printf("smoke: "+format+"\n", a...) }

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	var err error
	if hub := os.Getenv("WAVVON_SMOKE_HUB"); hub != "" {
		err = smoke(ctx, hub, os.Getenv("WAVVON_SMOKE_INVITE"), os.Getenv("WAVVON_SMOKE_CHANNEL"))
	} else {
		err = local(ctx)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "smoke: FAILED: %v\n", err)
		os.Exit(1)
	}
	step("PASSED")
}

func env(name, def string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return def
}

func newSeed() []byte {
	seed := make([]byte, 32)
	_, _ = rand.Read(seed)
	return seed
}

// local boots a hub binary, sets it up as owner and runs smoke against it.
func local(ctx context.Context) error {
	exe := "wavvon-hub"
	if runtime.GOOS == "windows" {
		exe += ".exe"
	}
	bin := env("WAVVON_HUB_BIN", filepath.Join("..", "..", "server", "target", "debug", exe))
	if _, err := os.Stat(bin); err != nil {
		return fmt.Errorf("no hub binary at %s; build Wavvon-server (cargo build -p wavvon-hub) or set WAVVON_HUB_BIN", bin)
	}
	container := env("WAVVON_PG_CONTAINER", "wavvon-pg")
	psql := func(sql string) error {
		out, err := exec.Command("docker", "exec", container, "psql", "-U", "postgres", "-c", sql).CombinedOutput()
		if err != nil {
			return fmt.Errorf("psql %q: %v: %s", sql, err, out)
		}
		return nil
	}

	// The hub keeps its identity and files in the working directory, and a
	// copied binary leaves the build output unlocked.
	dir, err := os.MkdirTemp("", "wavvon-sdk-go-smoke-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	hubBin := filepath.Join(dir, exe)
	if err := copyFile(bin, hubBin); err != nil {
		return err
	}

	if err := psql("DROP DATABASE IF EXISTS " + smokeDB); err != nil {
		return err
	}
	if err := psql("CREATE DATABASE " + smokeDB); err != nil {
		return err
	}
	defer func() {
		if err := psql("DROP DATABASE IF EXISTS " + smokeDB + " WITH (FORCE)"); err != nil {
			fmt.Fprintln(os.Stderr, "smoke:", err)
		}
	}()

	n, _ := rand.Int(rand.Reader, big.NewInt(500))
	port := 4400 + int(n.Int64())
	hubURL := fmt.Sprintf("http://localhost:%d", port)
	owner, err := wavvon.NewClient(wavvon.ClientOptions{HubURL: hubURL, Seed: newSeed()})
	if err != nil {
		return err
	}

	var log lockedBuffer
	cmd := exec.Command(hubBin)
	cmd.Dir = dir
	cmd.Stdout, cmd.Stderr = &log, &log
	cmd.Env = append(os.Environ(),
		"WAVVON_DATABASE_URL="+env("WAVVON_PG", "postgres://postgres:postgres@localhost:5432")+"/"+smokeDB,
		"WAVVON_ALLOW_PRIVATE_WEBHOOKS=true",
		fmt.Sprintf("WAVVON_HTTP_PORT=%d", port),
		fmt.Sprintf("WAVVON_VOICE_UDP_PORT=%d", port+1),
		"WAVVON_PUBLIC_URL="+hubURL,
		"WAVVON_OWNER_PUBKEY="+owner.Identity.PublicKey,
		"WAVVON_WEB_CLIENT_DIR=",
	)
	if err := cmd.Start(); err != nil {
		return err
	}
	exited := make(chan error, 1)
	go func() { exited <- cmd.Wait() }()
	// Kill only the process started here, then wait so its files can go.
	defer func() {
		_ = cmd.Process.Kill()
		<-exited
	}()

	deadline := time.Now().Add(90 * time.Second)
	for {
		select {
		case err := <-exited:
			exited <- err
			return fmt.Errorf("hub exited (%v)\n%s", err, log.String())
		default:
		}
		if res, err := http.Get(hubURL + "/info"); err == nil {
			res.Body.Close()
			if res.StatusCode == 200 {
				break
			}
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("hub never answered\n%s", log.String())
		}
		time.Sleep(400 * time.Millisecond)
	}
	step("hub up at %s", hubURL)

	role, err := wavvon.Check(owner.Rest.CreateRoleWithResponse(ctx, rest.CreateRoleJSONRequestBody{
		Name: "Apps", Priority: 10, Permissions: []string{"apps.register"},
	}))
	if err != nil || role.JSON201 == nil {
		return fmt.Errorf("create role: %v", err)
	}
	invite, err := wavvon.Check(owner.Rest.CreateInviteWithResponse(ctx, rest.CreateInviteJSONRequestBody{
		GrantRoleId: role.JSON201.Id, MaxUses: ptr[int64](1),
	}))
	if err != nil || invite.JSON201 == nil {
		return fmt.Errorf("create invite: %v", err)
	}
	channel, err := wavvon.Check(owner.Rest.CreateChannelWithResponse(ctx, rest.CreateChannelJSONRequestBody{Name: "sdk-smoke"}))
	if err != nil || channel.JSON201 == nil {
		return fmt.Errorf("create channel: %v", err)
	}
	step("role, invite and channel ready")

	err = smoke(ctx, hubURL, deref(invite.JSON201.Code), deref(channel.JSON201.Id))
	if err != nil && os.Getenv("WAVVON_SMOKE_VERBOSE") != "" {
		fmt.Println(log.String())
	}
	return err
}

func smoke(ctx context.Context, hubURL, inviteCode, channelID string) error {
	if inviteCode == "" {
		return errors.New("set WAVVON_SMOKE_INVITE")
	}
	client, err := wavvon.NewClient(wavvon.ClientOptions{
		HubURL: hubURL, Seed: newSeed(), InviteCode: inviteCode,
		Retry: wavvon.RetryOptions{OnRetry: func(i wavvon.RetryInfo) {
			step("retrying after status %d / %v (attempt %d)", i.Status, i.Err, i.Attempt)
		}},
	})
	if err != nil {
		return err
	}
	session, err := client.Login(ctx)
	if err != nil {
		return err
	}
	step("authenticated as %s (%s)", session.CanonicalPubkey, session.Scope)
	for _, c := range []string{"apps.register", "webhooks.signedtimestamp"} {
		if err := client.RequireCapability(ctx, c); err != nil {
			return err
		}
	}
	info, err := client.Info(ctx, false)
	if err != nil {
		return err
	}

	invocations := make(chan *wavvon.SlashInvocation, 1)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return err
	}
	srv := &http.Server{Handler: &wavvon.DispatchHandler{
		HubPublicKey: info.PublicKey,
		OnSlashCommand: func(_ context.Context, inv *wavvon.SlashInvocation) (*wavvon.AppResponse, error) {
			select {
			case invocations <- inv:
			default:
			}
			return &wavvon.AppResponse{Reply: &wavvon.Reply{Body: "pong: " + inv.ArgsRaw}}, nil
		},
	}}
	go func() { _ = srv.Serve(ln) }()
	defer srv.Close()
	webhookURL := fmt.Sprintf("http://%s:%d/hook", env("WAVVON_SMOKE_WEBHOOK_HOST", "localhost"), ln.Addr().(*net.TCPAddr).Port)

	if err := client.SetAppProfile(ctx, wavvon.AppProfile{Name: "SDK smoke", Description: ptr("Wavvon Go SDK smoke test"), WebhookUrl: &webhookURL}); err != nil {
		return err
	}
	if err := client.SetAppCommands(ctx, []wavvon.AppCommand{{Name: "sdksmoke", Description: "Answers pong", CooldownSeconds: ptr[int64](0)}}); err != nil {
		return err
	}
	step("registered /sdksmoke -> %s", webhookURL)

	// After the profile, so the hub treats this socket as an app's.
	stream := client.Connect(wavvon.EventStreamOptions{})
	defer stream.Close()
	var mu sync.Mutex
	var seen []wavvon.MessageEvent
	unknown := map[string]bool{}
	opened := make(chan struct{})
	go func() {
		for {
			ev, err := stream.Next(context.Background())
			if err != nil {
				return
			}
			mu.Lock()
			switch e := ev.(type) {
			case *wavvon.Hello:
				select {
				case <-opened:
				default:
					close(opened)
				}
			case *wavvon.MessageEvent:
				seen = append(seen, *e)
			case *wavvon.UnknownEvent:
				unknown[e.RawType] = true
			}
			mu.Unlock()
		}
	}()
	select {
	case <-opened:
	case <-time.After(10 * time.Second):
		return errors.New("timed out waiting for the socket")
	}
	step("socket open")

	if channelID == "" {
		chans, err := wavvon.Check(client.Rest.ListChannelsWithResponse(ctx))
		if err != nil {
			return err
		}
		for _, c := range deref(chans.JSON200) {
			if !deref(c.IsCategory) && (c.ChannelType == nil || *c.ChannelType == "text") {
				channelID = deref(c.Id)
				break
			}
		}
		if channelID == "" {
			return errors.New("no text channel to post in")
		}
	}

	waitFor := func(what string, pred func(wavvon.MessageEvent) bool) (wavvon.MessageEvent, error) {
		deadline := time.Now().Add(10 * time.Second)
		for time.Now().Before(deadline) {
			mu.Lock()
			i := slices.IndexFunc(seen, pred)
			var hit wavvon.MessageEvent
			if i >= 0 {
				hit = seen[i]
			}
			mu.Unlock()
			if i >= 0 {
				return hit, nil
			}
			time.Sleep(50 * time.Millisecond)
		}
		return wavvon.MessageEvent{}, fmt.Errorf("timed out waiting for %s", what)
	}
	post := func(content string) error {
		_, err := wavvon.Check(client.Rest.CreateChannelMessageWithResponse(ctx, channelID, rest.CreateChannelMessageJSONRequestBody{Content: content}))
		return err
	}

	text := fmt.Sprintf("hello from the Wavvon Go SDK %d", time.Now().UnixNano())
	if err := post(text); err != nil {
		return err
	}
	if _, err := waitFor("our own message over the socket", func(m wavvon.MessageEvent) bool { return deref(m.Message.Content) == text }); err != nil {
		return err
	}
	step("posted a message and saw it come back")

	if err := post("/sdksmoke ping"); err != nil {
		return err
	}
	reply, err := waitFor("the slash command reply", func(m wavvon.MessageEvent) bool { return deref(m.Message.Content) == "pong: ping" })
	if err != nil {
		return err
	}
	select {
	case inv := <-invocations:
		if inv.Command != "sdksmoke" || inv.ArgsRaw != "ping" {
			return fmt.Errorf("odd invocation %+v", inv)
		}
	default:
		return errors.New("the reply landed but the handler never saw the invocation")
	}
	if deref(reply.Message.Sender) != session.CanonicalPubkey {
		return fmt.Errorf("reply sent by %s", deref(reply.Message.Sender))
	}
	step("verified the invocation and the reply landed")

	mu.Lock()
	if len(unknown) > 0 {
		types := make([]string, 0, len(unknown))
		for t := range unknown {
			types = append(types, t)
		}
		slices.Sort(types)
		step("frames this SDK does not model (delivered as unknown): %s", strings.Join(types, ", "))
	}
	mu.Unlock()
	return nil
}

func ptr[T any](v T) *T { return &v }

func deref[T any](p *T) T {
	var zero T
	if p == nil {
		return zero
	}
	return *p
}

func copyFile(from, to string) error {
	in, err := os.Open(from)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(to, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o755)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}

type lockedBuffer struct {
	mu  sync.Mutex
	buf strings.Builder
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}
