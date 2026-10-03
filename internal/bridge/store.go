package bridge

import (
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
}
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
func (s *Store) issueLocked(user, client, scope string, o OAuthConfig, replaceRefresh string) (TokenResponse, error) {
	var out TokenResponse
	a, e := randomID()
	if e != nil {
		return out, e
	}
	r := ""
	if user != "" {
		r, e = randomID()
		if e != nil {
			return out, e
		}
	}
	now := time.Now().Unix()
	rec := TokenRecord{AccessHash: hashToken(a), UserID: user, ClientID: client, Scope: scope, AccessExpires: now + int64(o.AccessTTL)}
	if r != "" {
		rec.RefreshHash = hashToken(r)
		rec.RefreshExpires = now + int64(o.RefreshTTL)
	}
	next := make([]TokenRecord, 0, len(s.tokens)+1)
	for _, t := range s.tokens {
		if replaceRefresh != "" && t.RefreshHash == replaceRefresh {
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
	return s.issueLocked(user, client, scope, o, "")
}
func (s *Store) Refresh(refresh, client string, o OAuthConfig) (TokenResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	h := hashToken(refresh)
	for _, t := range s.tokens {
		if t.RefreshHash == h && t.ClientID == client && t.RefreshExpires > time.Now().Unix() {
			return s.issueLocked(t.UserID, client, t.Scope, o, h)
		}
	}
	return TokenResponse{}, apiError("invalid_grant", "refresh token invalid or expired")
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
