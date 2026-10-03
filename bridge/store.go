package bridge

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type TokenRecord struct {
	AccessHash     string `json:"accessHash"`
	RefreshHash    string `json:"refreshHash,omitempty"`
	UserID         string `json:"userId,omitempty"`
	ClientID       string `json:"clientId"`
	Scope          string `json:"scope,omitempty"`
	AccessExpires  int64  `json:"accessExpires"`
	RefreshExpires int64  `json:"refreshExpires,omitempty"`
	// PrevRefreshHash is the refresh token this record was rotated from. It
	// stays usable until PrevRefreshExpires so that a client whose refresh
	// response was lost can retry instead of losing the account link.
	PrevRefreshHash    string `json:"prevRefreshHash,omitempty"`
	PrevRefreshExpires int64  `json:"prevRefreshExpires,omitempty"`
	// The public nonce lets a retry derive the same pair from the presented
	// previous token. No recoverable bearer token or secret key is persisted.
	PrevRefreshNonce string `json:"prevRefreshNonce,omitempty"`
}

// refreshGrace is how long a rotated refresh token may be presented again.
const refreshGrace = 5 * 60

type tokenFile struct {
	Version int           `json:"version"`
	Tokens  []TokenRecord `json:"tokens"`
}
type Store struct {
	mu     sync.Mutex
	path   string
	tokens []TokenRecord
}
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token,omitempty"`
	Scope        string `json:"scope,omitempty"`
	Username     string `json:"username,omitempty"`
}

func randomID() (string, error) {
	b := make([]byte, 32)
	if _, e := rand.Read(b); e != nil {
		return "", e
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
func hashToken(s string) string { h := sha256.Sum256([]byte(s)); return hex.EncodeToString(h[:]) }
func OpenStore(path string) (*Store, error) {
	s := &Store{path: path, tokens: []TokenRecord{}}
	b, e := os.ReadFile(path)
	if os.IsNotExist(e) {
		return s, nil
	}
	if e != nil {
		return nil, e
	}
	var f tokenFile
	if e = json.Unmarshal(b, &f); e != nil {
		return nil, fmt.Errorf("token store: %w", e)
	}
	if f.Version != 1 {
		return nil, errors.New("unsupported token store version; do not use loki.json as dataFile")
	}
	for _, t := range f.Tokens {
		if len(t.AccessHash) != 64 || t.ClientID == "" {
			return nil, errors.New("invalid token store record")
		}
	}
	if e = os.Chmod(path, 0600); e != nil {
		return nil, e
	}
	s.tokens = f.Tokens
	return s, nil
}
func (s *Store) save(tokens []TokenRecord) error {
	dir := filepath.Dir(s.path)
	if e := os.MkdirAll(dir, 0700); e != nil {
		return e
	}
	b, e := json.MarshalIndent(tokenFile{1, tokens}, "", "  ")
	if e != nil {
		return e
	}
	f, e := os.CreateTemp(dir, ".tokens-*")
	if e != nil {
		return e
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if e = f.Chmod(0600); e != nil {
		f.Close()
		return e
	}
	if _, e = f.Write(b); e != nil {
		f.Close()
		return e
	}
	if e = f.Sync(); e != nil {
		f.Close()
		return e
	}
	if e = f.Close(); e != nil {
		return e
	}
	if e = os.Rename(tmp, s.path); e != nil {
		return e
	}
	// Directory fsync is best effort on filesystems that do not support it.
	if df, err := os.Open(dir); err == nil {
		_ = df.Sync()
		_ = df.Close()
	}
	return nil
}

type refreshRetry struct {
	token, nonce string
	expires      int64
}

// The previous refresh token is a 256-bit secret. Separate HMAC domains and a
// fresh random nonce give each rotation an unpredictable, reproducible pair.
func refreshPair(previous, nonce string) (access, refresh string) {
	derive := func(kind string) string {
		mac := hmac.New(sha256.New, []byte(previous))
		mac.Write([]byte("yandex2mqtt:refresh:v1:" + kind + ":" + nonce))
		return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	}
	return derive("access"), derive("refresh")
}

func (s *Store) issueLocked(user, client, scope string, o OAuthConfig, replace func(TokenRecord) bool, retry *refreshRetry) (TokenResponse, error) {
	var out TokenResponse
	var a, r string
	var e error
	if retry != nil {
		a, r = refreshPair(retry.token, retry.nonce)
	} else {
		a, e = randomID()
		if e != nil {
			return out, e
		}
		if user != "" {
			r, e = randomID()
			if e != nil {
				return out, e
			}
		}
	}
	now := time.Now().Unix()
	rec := TokenRecord{AccessHash: hashToken(a), UserID: user, ClientID: client, Scope: scope, AccessExpires: now + int64(o.AccessTTL)}
	if r != "" {
		rec.RefreshHash = hashToken(r)
		rec.RefreshExpires = now + int64(o.RefreshTTL)
	}
	if retry != nil {
		rec.PrevRefreshHash, rec.PrevRefreshExpires = hashToken(retry.token), retry.expires
		rec.PrevRefreshNonce = retry.nonce
	}
	next := make([]TokenRecord, 0, len(s.tokens)+1)
	for _, t := range s.tokens {
		if replace != nil && replace(t) {
			continue
		}
		if t.AccessExpires > now || t.RefreshExpires > now {
			next = append(next, t)
		}
	}
	next = append(next, rec)
	if e = s.save(next); e != nil {
		return out, e
	}
	s.tokens = next
	return TokenResponse{AccessToken: a, TokenType: "Bearer", ExpiresIn: o.AccessTTL, RefreshToken: r, Scope: scope}, nil
}
func (s *Store) Issue(user, client, scope string, o OAuthConfig) (TokenResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.issueLocked(user, client, scope, o, nil, nil)
}
func (s *Store) Refresh(refresh, client string, o OAuthConfig) (TokenResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	h := hashToken(refresh)
	now := time.Now().Unix()
	for _, t := range s.tokens {
		if t.RefreshHash == h && t.ClientID == client && t.RefreshExpires > now {
			return s.rotateLocked(t, refresh, o, min(now+refreshGrace, t.RefreshExpires, now+int64(o.AccessTTL)))
		}
	}
	for _, t := range s.tokens {
		if t.PrevRefreshHash == h && t.ClientID == client && t.PrevRefreshExpires > now && t.AccessExpires > now && t.RefreshExpires > now {
			if t.PrevRefreshNonce == "" {
				// Upgrade an in-flight 1.2.1 retry record once. Its random pair
				// cannot be recovered from hashes; subsequent retries are stable.
				return s.rotateLocked(t, refresh, o, min(t.PrevRefreshExpires, now+int64(o.AccessTTL)))
			}
			a, r := refreshPair(refresh, t.PrevRefreshNonce)
			if hashToken(a) != t.AccessHash || hashToken(r) != t.RefreshHash {
				return TokenResponse{}, apiError("invalid_grant", "invalid refresh retry record")
			}
			// Retry is read-only: neither the live pair nor its expiry changes.
			return TokenResponse{AccessToken: a, TokenType: "Bearer", ExpiresIn: int(t.AccessExpires - now), RefreshToken: r, Scope: t.Scope}, nil
		}
	}
	return TokenResponse{}, apiError("invalid_grant", "refresh token invalid or expired")
}
func (s *Store) rotateLocked(t TokenRecord, refresh string, o OAuthConfig, expires int64) (TokenResponse, error) {
	nonce, err := randomID()
	if err != nil {
		return TokenResponse{}, err
	}
	return s.issueLocked(t.UserID, t.ClientID, t.Scope, o, func(x TokenRecord) bool { return x.AccessHash == t.AccessHash }, &refreshRetry{token: refresh, nonce: nonce, expires: expires})
}
func (s *Store) Find(access string) (TokenRecord, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	h := hashToken(access)
	for _, t := range s.tokens {
		if t.AccessHash == h && t.AccessExpires > time.Now().Unix() {
			return t, true
		}
	}
	return TokenRecord{}, false
}
func (s *Store) Revoke(user, client string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	next := []TokenRecord{}
	for _, t := range s.tokens {
		if t.UserID == user && t.ClientID == client {
			continue
		}
		next = append(next, t)
	}
	if e := s.save(next); e != nil {
		return e
	}
	s.tokens = next
	return nil
}
func (s *Store) Linked(user, client string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now().Unix()
	for _, t := range s.tokens {
		if t.UserID == user && (client == "" || t.ClientID == client) && (t.AccessExpires > now || t.RefreshExpires > now) {
			return true
		}
	}
	return false
}
