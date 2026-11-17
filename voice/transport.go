package voice

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

// A minimal WebTransport client over quic-go's HTTP/3: an extended CONNECT,
// then HTTP/3 datagrams bound to that stream. Voice needs nothing else.
//
// Why not quic-go/webtransport-go (>= v0.11.1, the first release without
// CVE-2026-21435 and CVE-2026-57497)? Since v0.11.0 its client insists on the
// current draft's SETTINGS_WT_ENABLED (0x2c7cf000), while the hub's
// wtransport 0.7 sends only SETTINGS_ENABLE_WEBTRANSPORT (0x2b603742), the
// codepoint browsers and wtransport still speak: the dial fails with "server
// didn't enable WebTransport". This client sends and expects the latter and
// uses quic-go itself, which is current.
const (
	settingsEnableWebTransport = 0x2b603742
	draftOfferHeader           = "Sec-Webtransport-Http3-Draft02"
)

type wtSession struct {
	conn *quic.Conn
	tr   *http3.Transport
	str  *http3.RequestStream
}

// dialWebTransport connects to url (token already in its query). A non-empty
// certHash pins the hub's leaf certificate as serverCertificateHashes: system
// verification is off only in that branch.
func dialWebTransport(ctx context.Context, rawURL, certHash string) (*wtSession, error) {
	tlsCfg := &tls.Config{NextProtos: []string{http3.NextProtoH3}}
	if certHash != "" {
		want, err := hex.DecodeString(certHash)
		if err != nil || len(want) != sha256.Size {
			return nil, errors.New("voice_cert_hash is not a SHA-256 digest")
		}
		tlsCfg.InsecureSkipVerify = true
		tlsCfg.VerifyPeerCertificate = func(raw [][]byte, _ [][]*x509.Certificate) error {
			if len(raw) == 0 {
				return errors.New("the hub presented no certificate")
			}
			got := sha256.Sum256(raw[0])
			if subtle.ConstantTimeCompare(got[:], want) != 1 {
				return errors.New("the hub certificate does not match voice_cert_hash")
			}
			return nil
		}
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, err
	}
	conn, err := quic.DialAddr(ctx, u.Host, tlsCfg, &quic.Config{EnableDatagrams: true, KeepAlivePeriod: 5 * time.Second})
	if err != nil {
		return nil, err
	}
	tr := &http3.Transport{
		EnableDatagrams:    true,
		AdditionalSettings: map[uint64]uint64{settingsEnableWebTransport: 1},
	}
	fail := func(err error) (*wtSession, error) {
		conn.CloseWithError(0, "")
		_ = tr.Close()
		return nil, err
	}
	cc := tr.NewClientConn(conn)
	select {
	case <-cc.ReceivedSettings():
	case <-ctx.Done():
		return fail(fmt.Errorf("waiting for HTTP/3 settings: %w", ctx.Err()))
	}
	st := cc.Settings()
	if !st.EnableExtendedConnect {
		return fail(errors.New("server didn't enable Extended CONNECT"))
	}
	if !st.EnableDatagrams {
		return fail(errors.New("server didn't enable HTTP/3 datagrams"))
	}
	if st.Other[settingsEnableWebTransport] == 0 {
		return fail(errors.New("server didn't enable WebTransport"))
	}
	str, err := cc.OpenRequestStream(ctx)
	if err != nil {
		return fail(err)
	}
	req := (&http.Request{
		Method: http.MethodConnect,
		Proto:  "webtransport",
		Host:   u.Host,
		URL:    u,
		Header: http.Header{draftOfferHeader: {"1"}},
	}).WithContext(ctx)
	if err := str.SendRequestHeader(req); err != nil {
		return fail(err)
	}
	resp, err := str.ReadResponse()
	if err != nil {
		return fail(err)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fail(fmt.Errorf("the hub answered the WebTransport CONNECT with %d", resp.StatusCode))
	}
	return &wtSession{conn: conn, tr: tr, str: str}, nil
}

func (s *wtSession) SendDatagram(b []byte) error { return s.str.SendDatagram(b) }

func (s *wtSession) ReceiveDatagram(ctx context.Context) ([]byte, error) {
	return s.str.ReceiveDatagram(ctx)
}

func (s *wtSession) close(msg string) {
	s.str.CancelRead(0)
	s.str.CancelWrite(0)
	s.conn.CloseWithError(0, msg)
	_ = s.tr.Close()
}

func withToken(rawURL, token string) string {
	sep := "?"
	if strings.Contains(rawURL, "?") {
		sep = "&"
	}
	return rawURL + sep + "token=" + url.QueryEscape(token)
}
