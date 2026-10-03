package bridge

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log/slog"
	"os"
	"sync"
	"time"
)

// CertReloader picks up certificates renewed by an external tool. Checks occur
// on TLS handshakes, at most once per minute, using content rather than mtimes.
// A malformed, mismatched, expired or not-yet-valid replacement keeps the
// previously accepted certificate; failed candidates are retried later.
type CertReloader struct {
	certFile, keyFile string
	log               *slog.Logger
	interval          time.Duration
	mu                sync.Mutex
	cert              *tls.Certificate
	certHash, keyHash [32]byte
	lastCheck         time.Time
}

func (r *CertReloader) readPair() ([]byte, []byte, error) {
	cert, err := os.ReadFile(r.certFile)
	if err != nil {
		return nil, nil, err
	}
	key, err := os.ReadFile(r.keyFile)
	if err != nil {
		return nil, nil, err
	}
	return cert, key, nil
}

func validCertificate(certPEM, keyPEM []byte, now time.Time) (*tls.Certificate, error) {
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("TLS certificate: %w", err)
	}
	leaf := cert.Leaf
	if leaf == nil {
		leaf, err = x509.ParseCertificate(cert.Certificate[0])
		if err != nil {
			return nil, fmt.Errorf("TLS certificate: %w", err)
		}
	}
	if now.Before(leaf.NotBefore) || !now.Before(leaf.NotAfter) {
		return nil, fmt.Errorf("TLS certificate is outside its validity period")
	}
	return &cert, nil
}

func NewCertReloader(certFile, keyFile string, log *slog.Logger) (*CertReloader, error) {
	r := &CertReloader{certFile: certFile, keyFile: keyFile, log: log, interval: time.Minute}
	certPEM, keyPEM, err := r.readPair()
	if err != nil {
		return nil, err
	}
	now := time.Now()
	cert, err := validCertificate(certPEM, keyPEM, now)
	if err != nil {
		return nil, err
	}
	r.cert, r.certHash, r.keyHash, r.lastCheck = cert, sha256.Sum256(certPEM), sha256.Sum256(keyPEM), now
	return r, nil
}

func (r *CertReloader) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := time.Now()
	if now.Sub(r.lastCheck) < r.interval {
		return r.cert, nil
	}
	r.lastCheck = now
	certPEM, keyPEM, err := r.readPair()
	if err != nil {
		r.log.Error("TLS certificate check failed; keeping current certificate", "error", err.Error())
		return r.cert, nil
	}
	ch, kh := sha256.Sum256(certPEM), sha256.Sum256(keyPEM)
	if ch == r.certHash && kh == r.keyHash {
		return r.cert, nil
	}
	cert, err := validCertificate(certPEM, keyPEM, now)
	if err != nil {
		r.log.Error("TLS certificate reload failed; keeping current certificate", "error", err.Error())
		return r.cert, nil
	}
	r.cert, r.certHash, r.keyHash = cert, ch, kh
	r.log.Info("TLS certificate reloaded")
	return r.cert, nil
}
