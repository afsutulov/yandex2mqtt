package bridge

import (
	"container/list"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
)

type session struct {
	UserID, CSRF string
	Expires      time.Time
}
type authorization struct {
	ClientID, UserID, Redirect, State, Scope, ResponseType, Challenge string
	Expires                                                           time.Time
	Session                                                           string
}
type rateEntry struct {
	Count int
	Until time.Time
	Order *list.Element
}
type passwordCheck struct {
	cost int
	hash []byte
}
type oauthStatusWriter struct {
	http.ResponseWriter
	status int
}

func (w *oauthStatusWriter) WriteHeader(status int) {
	if w.status == 0 {
		w.status = status
		w.ResponseWriter.WriteHeader(status)
	}
}
func (w *oauthStatusWriter) Write(b []byte) (int, error) {
	if w.status == 0 {
		w.WriteHeader(http.StatusOK)
	}
	return w.ResponseWriter.Write(b)
}
func (w *oauthStatusWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

type Server struct {
	Config         Config
	Registry       *Registry
	Store          *Store
	Log            *slog.Logger
	mu             sync.Mutex
	sessions       map[string]session
	transactions   map[string]authorization
	codes          map[string]authorization
	rates          map[string]rateEntry
	rateOrder      list.List
	dummyHash      []byte
	passwordChecks []passwordCheck
	loginKey       []byte
	trustedProxies []netip.Prefix
}

func NewServer(c Config, r *Registry, st *Store, l *slog.Logger) (*Server, error) {
	s := &Server{Config: c, Registry: r, Store: st, Log: l, sessions: map[string]session{}, transactions: map[string]authorization{}, codes: map[string]authorization{}, rates: map[string]rateEntry{}}
	key, e := randomID()
	if e != nil {
		return nil, e
	}
	s.loginKey = []byte(key)
	for _, raw := range c.HTTP.TrustedProxies {
		prefix, e := netip.ParsePrefix(raw)
		if e != nil {
			return nil, e
		}
		s.trustedProxies = append(s.trustedProxies, prefix)
	}
	// Mixed-cost accounts must do the same total bcrypt work as an unknown
	// username. Build one check per configured cost; verify substitutes the
	// real hash only in its corresponding slot, without skipping any slots.
	costs := map[int]bool{}
	for _, u := range c.Users {
		uc := 12 // plaintext passwords are hashed with cost 12 below
		if u.PasswordHash != "" {
			if v, err := bcrypt.Cost([]byte(u.PasswordHash)); err == nil {
				uc = v
			}
		}
		costs[uc] = true
	}
	orderedCosts := make([]int, 0, len(costs))
	for cost := range costs {
		orderedCosts = append(orderedCosts, cost)
	}
	sort.Ints(orderedCosts)
	for _, cost := range orderedCosts {
		hash, err := bcrypt.GenerateFromPassword([]byte("invalid-user-dummy-password"), cost)
		if err != nil {
			return nil, err
		}
		s.passwordChecks = append(s.passwordChecks, passwordCheck{cost: cost, hash: hash})
		s.dummyHash = hash
	}
	for i := range s.Config.Users {
		u := &s.Config.Users[i]
		if u.PasswordHash == "" {
			h, e := bcrypt.GenerateFromPassword([]byte(u.Password), 12)
			if e != nil {
				return nil, e
			}
			u.PasswordHash = string(h)
		}
		u.Password = ""
	}
	return s, nil
}
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		s.page(w, "yandex2mqtt Go", template.HTML(`<p>Мост Яндекс Умный дом → MQTT.</p><p><a href="/account">Аккаунт</a></p>`))
	})
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		s.json(w, 200, map[string]any{"status": "ok", "mqtt_connected": s.Registry.pub.Connected()})
	})
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, r *http.Request) {
		status := 200
		if !s.Registry.pub.Connected() {
			status = 503
		}
		result := map[string]any{"mqtt_connected": s.Registry.pub.Connected()}
		if m, ok := s.Registry.pub.(interface{ SubscriptionStatus() SubscriptionStatus }); ok {
			result["subscriptions"] = m.SubscriptionStatus()
		}
		s.json(w, status, result)
	})
	mux.HandleFunc("GET /login", s.loginForm)
	mux.HandleFunc("POST /login", s.login)
	mux.HandleFunc("GET /account", s.account)
	mux.HandleFunc("GET /logout", s.logoutForm)
	mux.HandleFunc("POST /logout", s.logout)
	mux.HandleFunc("GET /dialog/authorize", s.authorize)
	mux.HandleFunc("POST /dialog/authorize/decision", s.decision)
	mux.HandleFunc("POST /oauth/token", s.token)
	mux.HandleFunc("GET /api/userinfo", s.userInfo)
	mux.HandleFunc("GET /api/clientinfo", s.clientInfo)
	for _, path := range []string{"/provider", "/provider/v1.0", "/v1.0"} {
		mux.HandleFunc("GET "+path, s.ping)
		mux.HandleFunc("HEAD "+path, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })
	}
	for _, base := range []string{"/provider/v1.0", "/v1.0"} {
		mux.HandleFunc("GET "+base+"/user/devices", s.devices)
		mux.HandleFunc("POST "+base+"/user/devices/query", s.query)
		mux.HandleFunc("POST "+base+"/user/devices/action", s.action)
		mux.HandleFunc("POST "+base+"/user/unlink", s.unlink)
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/login" || r.URL.Path == "/oauth/token" || r.URL.Path == "/dialog/authorize" || r.URL.Path == "/dialog/authorize/decision" {
			audit := &oauthStatusWriter{ResponseWriter: w}
			w = audit
			defer func() {
				status := audit.status
				if status == 0 {
					status = http.StatusOK
				}
				// Never log query strings, form data, Location or credentials.
				s.Log.Info("OAuth request", "method", r.Method, "path", r.URL.Path, "status", status)
			}()
		}
		defer func() {
			if v := recover(); v != nil {
				s.Log.Error("HTTP panic", "path", r.URL.Path)
				http.Error(w, "internal error", 500)
			}
		}()
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Content-Security-Policy", s.contentSecurityPolicy())
		w.Header().Set("Cache-Control", "no-store")
		r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
		canonical := r.URL.Path
		for strings.Contains(canonical, "//") {
			canonical = strings.ReplaceAll(canonical, "//", "/")
		}
		canonical = strings.TrimSuffix(canonical, "/")
		if canonical == "/provider" || strings.HasPrefix(canonical, "/provider/") || canonical == "/v1.0" || strings.HasPrefix(canonical, "/v1.0/") {
			r.URL.Path, r.URL.RawPath = canonical, ""
			s.Log.Info("provider request", "method", r.Method, "path", r.URL.Path, "request_id", r.Header.Get("X-Request-Id"))
		}
		mux.ServeHTTP(w, r)
	})
}
func (s *Server) json(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
func (s *Server) oauthError(w http.ResponseWriter, status int, code string) {
	s.Log.Warn("OAuth error", "status", status, "error", code)
	s.json(w, status, map[string]string{"error": code})
}
func (s *Server) user(id string) *User {
	for i := range s.Config.Users {
		if s.Config.Users[i].ID == id {
			return &s.Config.Users[i]
		}
	}
	return nil
}
func (s *Server) client(id string) *Client {
	for i := range s.Config.Clients {
		if s.Config.Clients[i].ClientID == id {
			return &s.Config.Clients[i]
		}
	}
	return nil
}
func (s *Server) verify(username, password string) *User {
	var u *User
	for i := range s.Config.Users {
		if s.Config.Users[i].Username == username {
			u = &s.Config.Users[i]
			break
		}
	}
	userCost := -1
	if u != nil {
		if cost, err := bcrypt.Cost([]byte(u.PasswordHash)); err == nil {
			userCost = cost
		}
	}
	matched := false
	for _, check := range s.passwordChecks {
		hash := check.hash
		real := u != nil && userCost == check.cost
		if real {
			hash = []byte(u.PasswordHash)
		}
		err := bcrypt.CompareHashAndPassword(hash, []byte(password))
		if real && err == nil {
			matched = true
		}
	}
	if matched {
		return u
	}
	return nil
}
func (s *Server) contentSecurityPolicy() string {
	origins := []string{"'self'"}
	for _, c := range s.Config.Clients {
		for _, raw := range c.RedirectURIs {
			u, e := url.Parse(raw)
			if e == nil && u.Scheme == "https" && u.Host != "" {
				origin := u.Scheme + "://" + u.Host
				if !contains(origins, origin) {
					origins = append(origins, origin)
				}
			}
		}
	}
	return "default-src 'none'; style-src 'unsafe-inline'; form-action " + strings.Join(origins, " ") + "; frame-ancestors 'none'; base-uri 'none'"
}
func (s *Server) trusted(addr netip.Addr) bool {
	for _, p := range s.trustedProxies {
		if p.Contains(addr.Unmap()) {
			return true
		}
	}
	return false
}
func (s *Server) ratePeer(r *http.Request) string {
	host, _, e := net.SplitHostPort(r.RemoteAddr)
	if e != nil {
		host = r.RemoteAddr
	}
	addr, e := netip.ParseAddr(host)
	if e != nil || !s.trusted(addr) {
		return host
	}
	forwarded := r.Header.Get("X-Forwarded-For")
	if forwarded == "" {
		if a, e := netip.ParseAddr(strings.TrimSpace(r.Header.Get("X-Real-IP"))); e == nil {
			return a.Unmap().String()
		}
		return host
	}
	chain := strings.Split(forwarded, ",")
	for i := len(chain) - 1; i >= 0; i-- {
		a, e := netip.ParseAddr(strings.TrimSpace(chain[i]))
		if e != nil {
			return host
		}
		host = a.Unmap().String()
		if !s.trusted(a) {
			return host
		}
	}
	return host
}

// rateKey groups IPv6 clients by /64: a single host normally controls a whole
// /64, so per-address keys would let one client fill the table and lock out
// everyone else.
func rateKey(peer string) string {
	a, e := netip.ParseAddr(peer)
	if e != nil {
		return peer
	}
	a = a.Unmap()
	if a.Is6() {
		if p, e := a.Prefix(64); e == nil {
			return p.String()
		}
	}
	return a.String()
}
func (s *Server) limited(r *http.Request, scope string) bool {
	host := scope + "|" + rateKey(s.ratePeer(r))
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	v, exists := s.rates[host]
	if !exists {
		// Capacity must bound memory, not reject every new user. Evict the
		// least recently used bucket; active offenders keep their quota.
		if len(s.rates) >= 10000 {
			oldest := s.rateOrder.Back()
			delete(s.rates, oldest.Value.(string))
			s.rateOrder.Remove(oldest)
		}
		v.Order = s.rateOrder.PushFront(host)
	} else {
		s.rateOrder.MoveToFront(v.Order)
	}
	if !now.Before(v.Until) {
		v.Count = 0
		v.Until = now.Add(time.Minute)
	}
	if v.Count < 31 {
		v.Count++
	}
	s.rates[host] = v
	return v.Count > 30
}
func (s *Server) cleanupLocked() {
	now := time.Now()
	for k, v := range s.sessions {
		if now.After(v.Expires) {
			delete(s.sessions, k)
		}
	}
	for k, v := range s.transactions {
		if now.After(v.Expires) {
			delete(s.transactions, k)
		}
	}
	for k, v := range s.codes {
		if now.After(v.Expires) {
			delete(s.codes, k)
		}
	}
}
func (s *Server) currentSession(r *http.Request) (string, session, bool) {
	c, e := r.Cookie("y2m_session")
	if e != nil {
		return "", session{}, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cleanupLocked()
	v, ok := s.sessions[c.Value]
	return c.Value, v, ok
}
func (s *Server) newSession(w http.ResponseWriter, user string) (string, session, error) {
	id, e := randomID()
	if e != nil {
		return "", session{}, e
	}
	csrf, e := randomID()
	if e != nil {
		return "", session{}, e
	}
	v := session{user, csrf, time.Now().Add(12 * time.Hour)}
	s.mu.Lock()
	s.cleanupLocked()
	if len(s.sessions) >= 10000 {
		s.mu.Unlock()
		return "", session{}, fmt.Errorf("too many sessions")
	}
	s.sessions[id] = v
	s.mu.Unlock()
	http.SetCookie(w, &http.Cookie{Name: "y2m_session", Value: id, Path: "/", HttpOnly: true, Secure: s.Config.HTTP.CookieSecure, SameSite: http.SameSiteLaxMode, MaxAge: 43200})
	return id, v, nil
}
func (s *Server) requireSession(w http.ResponseWriter, r *http.Request) (string, session, bool) {
	id, v, ok := s.currentSession(r)
	if !ok || v.UserID == "" {
		http.Redirect(w, r, "/login?return_to="+url.QueryEscape(r.URL.RequestURI()), http.StatusSeeOther)
		return "", session{}, false
	}
	return id, v, true
}
func csrfOK(r *http.Request, v session) bool {
	return v.CSRF != "" && subtle.ConstantTimeCompare([]byte(r.FormValue("csrf")), []byte(v.CSRF)) == 1
}
func safeReturn(raw string) string {
	u, e := url.Parse(raw)
	if e != nil || u.IsAbs() || u.Host != "" || !strings.HasPrefix(raw, "/") || strings.HasPrefix(raw, "//") || strings.ContainsAny(raw, "\\\r\n") {
		return "/account"
	}
	return raw
}

var pageTemplate = template.Must(template.New("page").Parse(`<!doctype html><html lang="ru"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>{{.Title}}</title><style>body{font:17px system-ui;max-width:520px;margin:8vh auto;padding:24px;color:#202530}input,button{font:inherit;box-sizing:border-box;padding:10px;margin:8px 0;width:100%}button{cursor:pointer}a{color:#1456b8}</style><h1>{{.Title}}</h1>{{.Body}}</html>`))

// A document navigation ends the consent POST before leaving this origin.
// Unlike a form redirect chain, meta refresh and the fallback link are not
// limited by form-action when the OAuth broker redirects to another origin.
var oauthReturnTemplate = template.Must(template.New("oauth-return").Parse(`<!doctype html><html lang="ru"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta http-equiv="refresh" content="0;url={{.URL}}"><title>Возвращение в приложение</title></head><body><p>Возвращаемся в приложение…</p><p><a href="{{.URL}}">Продолжить</a></p></body></html>`))

func (s *Server) page(w http.ResponseWriter, title string, body template.HTML) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = pageTemplate.Execute(w, struct {
		Title string
		Body  template.HTML
	}{title, body})
}
func escape(s string) string { return template.HTMLEscapeString(s) }
func (s *Server) loginForm(w http.ResponseWriter, r *http.Request) {
	_, v, ok := s.currentSession(r)
	if !ok {
		challenge, e := s.loginChallenge(w, r)
		v = session{CSRF: challenge}
		if e != nil {
			http.Error(w, "session error", 500)
			return
		}
		s.renderLogin(w, v, r.URL.Query().Get("return_to"))
		return
	}
	s.renderLogin(w, v, r.URL.Query().Get("return_to"))
}

// Anonymous CSRF challenges are signed and short-lived; GET /login allocates no session.
func (s *Server) signLoginChallenge(payload string) string {
	mac := hmac.New(sha256.New, s.loginKey)
	mac.Write([]byte(payload))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}
func (s *Server) validLoginChallenge(value string) bool {
	parts := strings.Split(value, ".")
	if len(parts) != 3 {
		return false
	}
	ts, e := strconv.ParseInt(parts[1], 10, 64)
	if e != nil {
		return false
	}
	age := time.Now().Unix() - ts
	if age < 0 || age > 600 {
		return false
	}
	signature, e := base64.RawURLEncoding.DecodeString(parts[2])
	if e != nil {
		return false
	}
	expected, _ := base64.RawURLEncoding.DecodeString(s.signLoginChallenge(parts[0] + "." + parts[1]))
	return len(parts[0]) == 43 && hmac.Equal(signature, expected)
}
func (s *Server) loginChallenge(w http.ResponseWriter, r *http.Request) (string, error) {
	if c, e := r.Cookie("y2m_login"); e == nil && s.validLoginChallenge(c.Value) {
		return c.Value, nil
	}
	nonce, e := randomID()
	if e != nil {
		return "", e
	}
	payload := nonce + "." + strconv.FormatInt(time.Now().Unix(), 10)
	value := payload + "." + s.signLoginChallenge(payload)
	http.SetCookie(w, &http.Cookie{Name: "y2m_login", Value: value, Path: "/", MaxAge: 600, HttpOnly: true, Secure: s.Config.HTTP.CookieSecure, SameSite: http.SameSiteLaxMode})
	return value, nil
}
func (s *Server) renderLogin(w http.ResponseWriter, v session, back string) {
	s.page(w, "Вход", template.HTML(`<form action="/login" method="post"><input type="hidden" name="csrf" value="`+escape(v.CSRF)+`"><input type="hidden" name="return_to" value="`+escape(safeReturn(back))+`"><label>Логин<input name="username" autocomplete="username" required maxlength="128"></label><label>Пароль<input type="password" name="password" autocomplete="current-password" required maxlength="72"></label><button>Войти</button></form>`))
}
func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	if s.limited(r, "login") {
		http.Error(w, "too many requests", 429)
		return
	}
	if e := r.ParseForm(); e != nil {
		http.Error(w, "bad form", 400)
		return
	}
	old, v, ok := s.currentSession(r)
	if !ok {
		if c, e := r.Cookie("y2m_login"); e == nil && s.validLoginChallenge(c.Value) {
			v = session{CSRF: c.Value}
			ok = true
		}
	}
	if !ok || !csrfOK(r, v) {
		http.Error(w, "CSRF rejected", 403)
		return
	}
	u := s.verify(r.FormValue("username"), r.FormValue("password"))
	if u == nil {
		http.Error(w, "Неверный логин или пароль", 401)
		return
	}
	if _, _, e := s.newSession(w, u.ID); e != nil {
		http.Error(w, "session error", 500)
		return
	}
	s.mu.Lock()
	delete(s.sessions, old)
	s.mu.Unlock()
	http.SetCookie(w, &http.Cookie{Name: "y2m_login", Path: "/", MaxAge: -1, HttpOnly: true, Secure: s.Config.HTTP.CookieSecure, SameSite: http.SameSiteLaxMode})
	http.Redirect(w, r, safeReturn(r.FormValue("return_to")), 303)
}
func (s *Server) account(w http.ResponseWriter, r *http.Request) {
	_, v, ok := s.requireSession(w, r)
	if !ok {
		return
	}
	u := s.user(v.UserID)
	if u == nil {
		http.Error(w, "unauthorized", 401)
		return
	}
	s.page(w, "Аккаунт", template.HTML(`<p>`+escape(u.Name)+` (`+escape(u.Username)+`)</p><p>Доступных устройств: `+fmt.Sprint(len(s.Registry.Discovery(u.ID)))+`</p><a href="/logout">Выйти</a>`))
}
func (s *Server) logoutForm(w http.ResponseWriter, r *http.Request) {
	_, v, ok := s.requireSession(w, r)
	if !ok {
		return
	}
	s.page(w, "Выход", template.HTML(`<form action="/logout" method="post"><input type="hidden" name="csrf" value="`+escape(v.CSRF)+`"><button>Выйти</button></form>`))
}
func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	id, v, ok := s.currentSession(r)
	if !ok || !csrfOK(r, v) {
		http.Error(w, "CSRF rejected", 403)
		return
	}
	s.mu.Lock()
	delete(s.sessions, id)
	s.mu.Unlock()
	http.SetCookie(w, &http.Cookie{Name: "y2m_session", Path: "/", MaxAge: -1, HttpOnly: true, Secure: s.Config.HTTP.CookieSecure, SameSite: http.SameSiteLaxMode})
	http.Redirect(w, r, "/", 303)
}
func (s *Server) authorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	client := s.client(q.Get("client_id"))
	redirect := q.Get("redirect_uri")
	if client == nil {
		s.Log.Warn("OAuth authorization rejected", "reason", "unknown_client")
		s.oauthError(w, 400, "invalid_request")
		return
	}
	if !contains(client.RedirectURIs, redirect) {
		s.Log.Warn("OAuth authorization rejected", "reason", "redirect_uri_mismatch")
		s.oauthError(w, 400, "invalid_request")
		return
	}
	response := q.Get("response_type")
	if response != "code" && !(response == "token" && s.Config.OAuth.AllowImplicit) {
		s.oauthError(w, 400, "unsupported_response_type")
		return
	}
	challenge := q.Get("code_challenge")
	if challenge != "" && (q.Get("code_challenge_method") != "S256" || len(challenge) != 43) {
		s.Log.Warn("OAuth authorization rejected", "reason", "invalid_pkce")
		s.oauthError(w, 400, "invalid_request")
		return
	}
	id, v, ok := s.requireSession(w, r)
	if !ok {
		return
	}
	a := authorization{ClientID: client.ClientID, UserID: v.UserID, Redirect: redirect, State: q.Get("state"), Scope: q.Get("scope"), ResponseType: response, Challenge: challenge, Expires: time.Now().Add(time.Duration(s.Config.OAuth.CodeTTL) * time.Second), Session: id}
	if client.Trusted {
		s.finishAuthorization(w, r, a, true)
		return
	}
	tx, e := randomID()
	if e != nil {
		http.Error(w, "authorization error", 500)
		return
	}
	s.mu.Lock()
	s.cleanupLocked()
	if len(s.transactions) >= 10000 {
		s.mu.Unlock()
		http.Error(w, "too many transactions", 503)
		return
	}
	s.transactions[tx] = a
	s.mu.Unlock()
	s.page(w, "Разрешение доступа", template.HTML(`<p>Разрешить приложению «`+escape(client.Name)+`» управлять доступными вам устройствами?</p><form action="/dialog/authorize/decision" method="post"><input type="hidden" name="csrf" value="`+escape(v.CSRF)+`"><input type="hidden" name="transaction_id" value="`+escape(tx)+`"><button name="approve" value="yes">Разрешить</button><button name="approve" value="no">Отказать</button></form>`))
}
func (s *Server) decision(w http.ResponseWriter, r *http.Request) {
	id, v, ok := s.currentSession(r)
	if !ok || !csrfOK(r, v) {
		http.Error(w, "CSRF rejected", 403)
		return
	}
	tx := r.FormValue("transaction_id")
	s.mu.Lock()
	s.cleanupLocked()
	a, found := s.transactions[tx]
	if found && a.Session == id && a.UserID == v.UserID {
		delete(s.transactions, tx)
	} else {
		found = false
	}
	s.mu.Unlock()
	if !found {
		s.Log.Warn("OAuth consent rejected", "reason", "expired_or_reused_transaction")
		s.oauthError(w, 400, "invalid_request")
		return
	}
	s.finishAuthorization(w, r, a, r.FormValue("approve") == "yes")
}
func (s *Server) finishAuthorization(w http.ResponseWriter, r *http.Request, a authorization, approved bool) {
	u, _ := url.Parse(a.Redirect)
	q := u.Query()
	q.Set("state", a.State)
	q.Set("client_id", a.ClientID)
	if a.Scope != "" {
		q.Set("scope", a.Scope)
	}
	if !approved {
		q.Set("error", "access_denied")
	} else if a.ResponseType == "code" {
		code, e := randomID()
		if e != nil {
			http.Error(w, "authorization error", 500)
			return
		}
		s.mu.Lock()
		s.cleanupLocked()
		if len(s.codes) >= 10000 {
			s.mu.Unlock()
			http.Error(w, "too many codes", 503)
			return
		}
		s.codes[hashToken(code)] = a
		s.mu.Unlock()
		q.Set("code", code)
	} else {
		t, e := s.Store.Issue(a.UserID, a.ClientID, a.Scope, s.Config.OAuth)
		if e != nil {
			http.Error(w, "storage error", 500)
			return
		}
		fragment := url.Values{"access_token": {t.AccessToken}, "token_type": {"Bearer"}, "expires_in": {fmt.Sprint(t.ExpiresIn)}, "state": {a.State}}
		u.Fragment = fragment.Encode()
	}
	u.RawQuery = q.Encode()
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := oauthReturnTemplate.Execute(w, struct{ URL string }{u.String()}); err != nil {
		s.Log.Error("OAuth return page failed")
	}
}
func (s *Server) token(w http.ResponseWriter, r *http.Request) {
	if e := r.ParseForm(); e != nil {
		s.oauthError(w, 400, "invalid_request")
		return
	}
	id, secret, hasBasic := r.BasicAuth()
	if !hasBasic {
		id = r.FormValue("client_id")
		secret = r.FormValue("client_secret")
	}
	matches := func(id, secret string) *Client {
		c := s.client(id)
		if c == nil || subtle.ConstantTimeCompare([]byte(secret), []byte(c.Secret)) != 1 {
			return nil
		}
		return c
	}
	c := matches(id, secret)
	// RFC 6749 encodes Basic fields as form data. Also accept conventional raw Basic.
	if c == nil && hasBasic {
		decodedID, e1 := url.QueryUnescape(id)
		decodedSecret, e2 := url.QueryUnescape(secret)
		if e1 == nil && e2 == nil {
			c = matches(decodedID, decodedSecret)
			if c != nil {
				id = decodedID
			}
		}
	}
	if c == nil || hasBasic && r.FormValue("client_id") != "" && r.FormValue("client_id") != id {
		if s.limited(r, "invalid-client") {
			s.oauthError(w, 429, "slow_down")
			return
		}
		w.Header().Set("WWW-Authenticate", `Basic realm="OAuth"`)
		s.oauthError(w, 401, "invalid_client")
		return
	}
	// Limits for failed logins/invalid client credentials never consume a valid grant's quota.
	// Use a hash of the grant proof to isolate different users behind the same proxy.
	scope := "grant:" + id + ":" + r.FormValue("grant_type") + ":" + hashToken(r.FormValue("refresh_token")+r.FormValue("code"))
	if r.FormValue("grant_type") == "password" {
		scope = "login"
	}
	if s.limited(r, scope) {
		s.oauthError(w, 429, "slow_down")
		return
	}
	var t TokenResponse
	var e error
	switch r.FormValue("grant_type") {
	case "authorization_code":
		key := hashToken(r.FormValue("code"))
		s.mu.Lock()
		s.cleanupLocked()
		a, ok := s.codes[key]
		valid := ok && a.ClientID == id && a.Redirect == r.FormValue("redirect_uri") && s.user(a.UserID) != nil
		if valid && a.Challenge != "" {
			verifier := r.FormValue("code_verifier")
			h := sha256Base64(verifier)
			valid = len(verifier) >= 43 && len(verifier) <= 128 && h == a.Challenge
		}
		if valid {
			delete(s.codes, key)
		}
		s.mu.Unlock()
		if !valid {
			s.oauthError(w, 400, "invalid_grant")
			return
		}
		t, e = s.Store.Issue(a.UserID, id, a.Scope, s.Config.OAuth)
		if e == nil {
			t.Username = s.user(a.UserID).Username
		}
	case "refresh_token":
		t, e = s.Store.Refresh(r.FormValue("refresh_token"), id, s.Config.OAuth)
	case "password":
		if !s.Config.OAuth.AllowPassword {
			s.oauthError(w, 400, "unsupported_grant_type")
			return
		}
		u := s.verify(r.FormValue("username"), r.FormValue("password"))
		if u == nil {
			s.oauthError(w, 400, "invalid_grant")
			return
		}
		t, e = s.Store.Issue(u.ID, id, r.FormValue("scope"), s.Config.OAuth)
	case "client_credentials":
		if !s.Config.OAuth.AllowClientCredentials {
			s.oauthError(w, 400, "unsupported_grant_type")
			return
		}
		t, e = s.Store.Issue("", id, r.FormValue("scope"), s.Config.OAuth)
	default:
		s.oauthError(w, 400, "unsupported_grant_type")
		return
	}
	if e != nil {
		if ae, ok := e.(*APIError); ok {
			s.oauthError(w, 400, ae.Code)
		} else {
			s.Log.Error("token storage failed")
			s.oauthError(w, 500, "server_error")
		}
		return
	}
	s.json(w, 200, t)
}
func (s *Server) bearer(w http.ResponseWriter, r *http.Request, needUser bool) (TokenRecord, bool) {
	p := strings.Fields(r.Header.Get("Authorization"))
	if len(p) != 2 || !strings.EqualFold(p[0], "Bearer") {
		w.Header().Set("WWW-Authenticate", `Bearer`)
		http.Error(w, "unauthorized", 401)
		return TokenRecord{}, false
	}
	t, ok := s.Store.Find(p[1])
	if !ok || s.client(t.ClientID) == nil || needUser && s.user(t.UserID) == nil {
		w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
		http.Error(w, "unauthorized", 401)
		return TokenRecord{}, false
	}
	return t, true
}
func (s *Server) userInfo(w http.ResponseWriter, r *http.Request) {
	t, ok := s.bearer(w, r, true)
	if !ok {
		return
	}
	s.json(w, 200, map[string]any{"user_id": t.UserID, "name": s.user(t.UserID).Name, "scope": t.Scope})
}
func (s *Server) clientInfo(w http.ResponseWriter, r *http.Request) {
	t, ok := s.bearer(w, r, false)
	if !ok {
		return
	}
	s.json(w, 200, map[string]any{"client_id": t.ClientID, "name": s.client(t.ClientID).Name, "scope": t.Scope})
}
func (s *Server) ping(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("OK"))
}

func (s *Server) devices(w http.ResponseWriter, r *http.Request) {
	t, ok := s.bearer(w, r, true)
	if !ok {
		return
	}
	s.json(w, 200, map[string]any{"request_id": r.Header.Get("X-Request-Id"), "payload": map[string]any{"user_id": t.UserID, "devices": s.Registry.Discovery(t.UserID)}})
}

type requestDevice struct {
	ID           string `json:"id"`
	Capabilities []struct {
		Type  string `json:"type"`
		State State  `json:"state"`
	} `json:"capabilities"`
}

func decodeBody(r *http.Request, out any) error {
	d := json.NewDecoder(r.Body)
	if e := d.Decode(out); e != nil {
		return e
	}
	if d.Decode(new(any)) != io.EOF {
		return fmt.Errorf("one JSON object required")
	}
	return nil
}
func validDevices(ds []requestDevice) bool {
	if ds == nil || len(ds) > 100 {
		return false
	}
	for _, d := range ds {
		if d.ID == "" || len(d.Capabilities) > 32 {
			return false
		}
	}
	return true
}
func (s *Server) query(w http.ResponseWriter, r *http.Request) {
	t, ok := s.bearer(w, r, true)
	if !ok {
		return
	}
	var req struct {
		Devices []requestDevice `json:"devices"`
	}
	if decodeBody(r, &req) != nil || !validDevices(req.Devices) {
		http.Error(w, "invalid devices body", 400)
		return
	}
	out := []map[string]any{}
	for _, d := range req.Devices {
		out = append(out, s.Registry.Query(t.UserID, d.ID))
	}
	s.json(w, 200, map[string]any{"request_id": r.Header.Get("X-Request-Id"), "payload": map[string]any{"devices": out}})
}
func (s *Server) action(w http.ResponseWriter, r *http.Request) {
	// Yandex's 3-second budget includes both network trips. Reserve 500ms
	// for transport and response encoding; start counting before decoding.
	ctx, cancel := context.WithTimeout(r.Context(), 2500*time.Millisecond)
	defer cancel()
	t, ok := s.bearer(w, r, true)
	if !ok {
		return
	}
	var req struct {
		Payload struct {
			Devices []requestDevice `json:"devices"`
		} `json:"payload"`
	}
	if decodeBody(r, &req) != nil || !validDevices(req.Payload.Devices) {
		http.Error(w, "invalid action body", 400)
		return
	}
	out := make([]map[string]any, len(req.Payload.Devices))
	groups := map[string][]int{}
	for i, d := range req.Payload.Devices {
		groups[d.ID] = append(groups[d.ID], i)
	}
	var wg sync.WaitGroup
	for _, indices := range groups {
		wg.Add(1)
		go func(indices []int) {
			defer wg.Done()
			for _, index := range indices {
				d := req.Payload.Devices[index]
				func() {
					defer func() {
						if recover() != nil {
							s.Log.Error("action panic", "device", d.ID)
							out[index] = map[string]any{"id": d.ID, "action_result": errorResult(apiError("INTERNAL_ERROR", "internal error"))}
						}
					}()
					m := map[string]any{"id": d.ID}
					if !s.Registry.HasAccess(t.UserID, d.ID) {
						m["action_result"] = errorResult(apiError("DEVICE_NOT_FOUND", "device unavailable to this user"))
					} else if len(d.Capabilities) == 0 {
						m["action_result"] = errorResult(apiError("INVALID_ACTION", "capabilities required"))
					} else {
						caps := []map[string]any{}
						for _, cap := range d.Capabilities {
							e := s.Registry.Act(ctx, t.UserID, d.ID, cap.Type, cap.State)
							res := map[string]any{"status": "DONE"}
							if e != nil {
								res = errorResult(e)
							}
							caps = append(caps, map[string]any{"type": cap.Type, "state": map[string]any{"instance": cap.State.Instance, "action_result": res}})
						}
						m["capabilities"] = caps
					}
					out[index] = m
				}()
			}
		}(indices)
	}
	wg.Wait()
	s.json(w, 200, map[string]any{"request_id": r.Header.Get("X-Request-Id"), "payload": map[string]any{"devices": out}})
}
func (s *Server) unlink(w http.ResponseWriter, r *http.Request) {
	t, ok := s.bearer(w, r, true)
	if !ok {
		return
	}
	if e := s.Store.Revoke(t.UserID, t.ClientID); e != nil {
		http.Error(w, "storage error", 500)
		return
	}
	s.mu.Lock()
	for key, a := range s.codes {
		if a.UserID == t.UserID && a.ClientID == t.ClientID {
			delete(s.codes, key)
		}
	}
	for key, a := range s.transactions {
		if a.UserID == t.UserID && a.ClientID == t.ClientID {
			delete(s.transactions, key)
		}
	}
	s.mu.Unlock()
	s.json(w, 200, map[string]string{"request_id": r.Header.Get("X-Request-Id")})
}
