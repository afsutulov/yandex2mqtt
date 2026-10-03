package bridge

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io"
	"log/slog"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
)

func TestFinalReviewMixedPasswordCosts(t *testing.T) {
	c := testConfig(t)
	h, err := bcrypt.GenerateFromPassword([]byte("high-cost-password"), 12)
	if err != nil {
		t.Fatal(err)
	}
	c.Users[1].PasswordHash = string(h)
	st, err := OpenStore(c.DataFile)
	if err != nil {
		t.Fatal(err)
	}
	s, err := NewServer(c, NewRegistry(c, &fakePublisher{}), st, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	// Alternate samples to reduce load drift; the old path is about four
	// times faster for alice (cost 10) than an unknown username (cost 12).
	var known, unknown time.Duration
	for range 4 {
		start := time.Now()
		if s.verify("alice", "wrong-password") != nil {
			t.Fatal("wrong password accepted")
		}
		known += time.Since(start)
		start = time.Now()
		if s.verify("missing", "wrong-password") != nil {
			t.Fatal("unknown user accepted")
		}
		unknown += time.Since(start)
	}
	if float64(known)/float64(unknown) < 0.65 || float64(known)/float64(unknown) > 1.55 {
		t.Fatalf("mixed costs expose username: known=%s unknown=%s", known/4, unknown/4)
	}
	if s.verify("alice", "test-password") == nil || s.verify("bob", "high-cost-password") == nil {
		t.Fatal("mixed-cost users cannot authenticate")
	}
}

func TestFinalReviewEstimatedStateNotification(t *testing.T) {
	c := testConfig(t)
	c.Devices[0].MQTT[0].State = ""
	c.Devices[0].Capabilities[0].State = &State{Instance: "on", Value: false}
	r, p := regressionRegistry(t, c)
	changes := []Change{}
	r.OnChange = func(change Change) {
		// A callback must observe the committed state without a held state mutex.
		q := r.Query("1", "lamp")
		if q["error_code"] != nil {
			t.Error(q)
		}
		changes = append(changes, change)
	}
	act := func(value bool) error {
		return r.Act(context.Background(), "1", "lamp", onOff, State{Instance: "on", Value: value})
	}
	if err := act(true); err != nil {
		t.Fatal(err)
	}
	if len(changes) != 1 {
		t.Fatalf("reportable estimated state did not emit a callback: %d", len(changes))
	}
	if changes[0].Capabilities[0]["state"].(map[string]any)["value"] != true {
		t.Fatal(changes)
	}
	if err := act(true); err != nil {
		t.Fatal(err)
	}
	if len(changes) != 1 {
		t.Fatal("unchanged value emitted duplicate callback")
	}
	p.err = errors.New("rejected")
	if err := act(false); err == nil || len(changes) != 1 {
		t.Fatal("failed publication emitted an estimated state")
	}
	// A feature explicitly disabling reports must still update query only.
	p.err = nil
	r.devices["lamp"].config.Capabilities[0].Reportable = false
	if err := act(false); err != nil || len(changes) != 1 {
		t.Fatal("non-reportable state emitted a callback", err)
	}
}

func TestFinalReviewIncrementalEstimatedState(t *testing.T) {
	initial := &State{Instance: "volume", Value: float64(30)}
	r, p := commandOnlyRange(t, initial)
	f := &r.devices["lamp"].config.Capabilities[0]
	f.Parameters["random_access"] = false
	f.Retrievable = true
	f.Reportable = true
	changes := []Change{}
	r.OnChange = func(change Change) { changes = append(changes, change) }
	for _, delta := range []float64{10, -5} {
		if err := r.Act(context.Background(), "1", "lamp", f.Type, State{Instance: "volume", Value: delta, Relative: true}); err != nil {
			t.Fatal(err)
		}
	}
	caps := r.Query("1", "lamp")["capabilities"].([]map[string]any)
	if value := caps[0]["state"].(map[string]any)["value"]; value != float64(35) {
		t.Fatal("incremental estimate stays frozen at initial state", value)
	}
	if len(changes) != 2 || p.messages[0] != "volume/set=10" || p.messages[1] != "volume/set=-5" {
		t.Fatal("estimate changes MQTT delta semantics", changes, p.messages)
	}
}

func TestFinalReviewCertificateRenewalPreservesTimestamp(t *testing.T) {
	dir := t.TempDir()
	cert, key := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	writeTestCert(t, cert, key, "first")
	cm, err := os.Stat(cert)
	if err != nil {
		t.Fatal(err)
	}
	km, err := os.Stat(key)
	if err != nil {
		t.Fatal(err)
	}
	r, err := NewCertReloader(cert, key, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	r.interval = 0
	writeTestCert(t, cert, key, "renewed")
	if err := os.Chtimes(cert, cm.ModTime(), cm.ModTime()); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(key, km.ModTime(), km.ModTime()); err != nil {
		t.Fatal(err)
	}
	c, err := r.GetCertificate(&tls.ClientHelloInfo{})
	if err != nil {
		t.Fatal(err)
	}
	x, err := x509.ParseCertificate(c.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	if x.Subject.CommonName != "renewed" {
		t.Fatal("renewed content ignored because mtimes stayed equal")
	}
}

func TestFinalReviewCertificateRejectsExpiredRenewal(t *testing.T) {
	dir := t.TempDir()
	cert, key := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	writeTestCert(t, cert, key, "working")
	r, err := NewCertReloader(cert, key, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	r.interval = 0
	working, err := r.GetCertificate(&tls.ClientHelloInfo{})
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(working.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	leaf.SerialNumber = big.NewInt(1234)
	leaf.NotBefore = time.Now().Add(-2 * time.Hour)
	leaf.NotAfter = time.Now().Add(-time.Hour)
	private := working.PrivateKey.(*ecdsa.PrivateKey)
	der, err := x509.CreateCertificate(rand.Reader, leaf, leaf, &private.PublicKey, private)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cert, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600); err != nil {
		t.Fatal(err)
	}
	stamp := time.Now().Add(time.Second)
	if err := os.Chtimes(cert, stamp, stamp); err != nil {
		t.Fatal(err)
	}
	after, err := r.GetCertificate(&tls.ClientHelloInfo{})
	if err != nil {
		t.Fatal(err)
	}
	x, err := x509.ParseCertificate(after.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	if !x.NotAfter.After(time.Now()) {
		t.Fatal("expired replacement disabled a working TLS endpoint")
	}
	if _, err := NewCertReloader(cert, key, slog.New(slog.NewTextHandler(io.Discard, nil))); err == nil {
		t.Fatal("startup accepted an expired certificate")
	}
	leaf.NotBefore = time.Now().Add(time.Hour)
	leaf.NotAfter = time.Now().Add(2 * time.Hour)
	der, err = x509.CreateCertificate(rand.Reader, leaf, leaf, &private.PublicKey, private)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cert, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600); err != nil {
		t.Fatal(err)
	}
	after, err = r.GetCertificate(&tls.ClientHelloInfo{})
	if err != nil {
		t.Fatal(err)
	}
	x, err = x509.ParseCertificate(after.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	if x.NotBefore.After(time.Now()) {
		t.Fatal("not-yet-valid certificate replaced working TLS")
	}
	writeTestCert(t, cert, key, "restored")
	after, err = r.GetCertificate(&tls.ClientHelloInfo{})
	if err != nil {
		t.Fatal(err)
	}
	x, err = x509.ParseCertificate(after.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	if x.Subject.CommonName != "restored" {
		t.Fatal("failed renewal permanently blocked a later valid certificate")
	}
}
