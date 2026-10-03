package bridge

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"html"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
)

const onOff = "devices.capabilities.on_off"

type fakePublisher struct {
	online   atomic.Bool
	mu       sync.Mutex
	messages []string
	err      error
	hook     func(string, []byte)
}

func (p *fakePublisher) Connected() bool { return p.online.Load() }
func (p *fakePublisher) Publish(ctx context.Context, t string, b []byte) error {
	if e := ctx.Err(); e != nil {
		return e
	}
	p.mu.Lock()
	p.messages = append(p.messages, t+"="+string(b))
	hook, e := p.hook, p.err
	p.mu.Unlock()
	if hook != nil {
		hook(t, b)
	}
	return e
}
func (p *fakePublisher) count() int { p.mu.Lock(); defer p.mu.Unlock(); return len(p.messages) }

var testHash string
var hashOnce sync.Once

func testConfig(t *testing.T) Config {
	t.Helper()
	hashOnce.Do(func() {
		h, e := bcrypt.GenerateFromPassword([]byte("test-password"), 10)
		if e != nil {
			panic(e)
		}
		testHash = string(h)
	})
	c := Config{Users: []User{{ID: "1", Username: "alice", Name: "Alice", PasswordHash: testHash}, {ID: "2", Username: "bob", Name: "Bob", PasswordHash: testHash}}, Clients: []Client{{ID: "internal-1", Name: "Yandex", ClientID: "yandex-client", Secret: "client-secret", RedirectURIs: []string{"https://social.yandex.net/broker/redirect"}}, {ID: "internal-2", Name: "Other", ClientID: "other-client", Secret: "other-secret", RedirectURIs: []string{"https://example.org/callback"}}}, DataFile: filepath.Join(t.TempDir(), "tokens.json"), Devices: []DeviceConfig{{ID: "lamp", Name: "Lamp", Type: "devices.types.light", AllowedUsers: []string{"1"}, MQTT: []Binding{{Instance: "on", Set: "home/lamp/set", State: "home/Lamp/state"}}, Capabilities: []Feature{{Type: onOff, Retrievable: true, Reportable: true}}, ValueMapping: []ValueMapping{{Type: "on_off", Mapping: [][]any{{false, true}, {float64(0), float64(1)}}}}}}}
	c.Defaults()
	if e := c.Validate(); e != nil {
		t.Fatal(e)
	}
	return c
}
func fixture(t *testing.T) (*Server, *Registry, *fakePublisher) {
	t.Helper()
	c := testConfig(t)
	p := &fakePublisher{}
	p.online.Store(true)
	r := NewRegistry(c, p)
	st, e := OpenStore(c.DataFile)
	if e != nil {
		t.Fatal(e)
	}
	s, e := NewServer(c, r, st, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if e != nil {
		t.Fatal(e)
	}
	return s, r, p
}
func request(t *testing.T, s *Server, method, path, token, body string) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	r.Header.Set("X-Request-Id", "test-request-id")
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	return w
}
func issue(t *testing.T, s *Server, user, client string) TokenResponse {
	t.Helper()
	tok, e := s.Store.Issue(user, client, "home", s.Config.OAuth)
	if e != nil {
		t.Fatal(e)
	}
	return tok
}
func decodeResponse(t *testing.T, w *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var v map[string]any
	if e := json.Unmarshal(w.Body.Bytes(), &v); e != nil {
		t.Fatal(w.Body.String(), e)
	}
	return v
}
func TestDeviceIsolationAndUnknownDevices(t *testing.T) {
	s, r, p := fixture(t)
	a := issue(t, s, "1", "yandex-client")
	b := issue(t, s, "2", "yandex-client")
	r.Update("home/Lamp/state", []byte("1"))
	for _, token := range []string{a.AccessToken, b.AccessToken} {
		w := request(t, s, "GET", "/provider/v1.0/user/devices", token, "")
		if w.Code != 200 {
			t.Fatal(w.Code)
		}
		if strings.Contains(w.Body.String(), "custom_data") || strings.Contains(w.Body.String(), "home/Lamp") {
			t.Fatal("MQTT internals leaked")
		}
	}
	for _, id := range []string{"lamp", "missing"} {
		w := request(t, s, "POST", "/provider/v1.0/user/devices/query", b.AccessToken, `{"devices":[{"id":"`+id+`"}]}`)
		if w.Code != 200 || !strings.Contains(w.Body.String(), "DEVICE_NOT_FOUND") {
			t.Fatal(w.Body.String())
		}
		w = request(t, s, "POST", "/provider/v1.0/user/devices/action", b.AccessToken, `{"payload":{"devices":[{"id":"`+id+`","capabilities":[{"type":"`+onOff+`","state":{"instance":"on","value":true}}]}]}}`)
		if w.Code != 200 || !strings.Contains(w.Body.String(), "DEVICE_NOT_FOUND") {
			t.Fatal(w.Body.String())
		}
	}
	if p.count() != 0 {
		t.Fatal("unauthorized MQTT publish")
	}
}
func TestMappingTopicCaseAndSharedTopic(t *testing.T) {
	c := testConfig(t)
	dc := c.Devices[0]
	dc.ID = "lamp2"
	c.Devices = append(c.Devices, dc)
	p := &fakePublisher{}
	p.online.Store(true)
	r := NewRegistry(c, p)
	if len(r.Update("home/lamp/state", []byte("1"))) != 0 {
		t.Fatal("unexpected error")
	}
	if r.Query("1", "lamp")["error_code"] != "DEVICE_UNREACHABLE" {
		t.Fatal("case-insensitive topic matching")
	}
	if e := r.Update("home/Lamp/state", []byte("1")); len(e) > 0 {
		t.Fatal(e)
	}
	for _, id := range []string{"lamp", "lamp2"} {
		m := r.Query("1", id)
		caps := m["capabilities"].([]map[string]any)
		if caps[0]["state"].(map[string]any)["value"] != true {
			t.Fatal(m)
		}
	}
	if e := r.Act(context.Background(), "1", "lamp", onOff, State{Instance: "on", Value: false}); e != nil {
		t.Fatal(e)
	}
	if p.messages[0] != "home/lamp/set=0" {
		t.Fatal(p.messages)
	}
	if r.Query("1", "lamp")["capabilities"].([]map[string]any)[0]["state"].(map[string]any)["value"] != true {
		t.Fatal("command incorrectly overwrote MQTT state")
	}
}
func TestInvalidStatesAndActionErrors(t *testing.T) {
	s, r, p := fixture(t)
	tok := issue(t, s, "1", "yandex-client")
	if len(r.Update("home/Lamp/state", []byte("garbage"))) != 1 {
		t.Fatal("invalid state accepted")
	}
	if r.Query("1", "lamp")["error_code"] != "DEVICE_UNREACHABLE" {
		t.Fatal("invented initial state")
	}
	tests := []struct {
		typ   string
		value any
		err   string
	}{{onOff, "true", "INVALID_VALUE"}, {"devices.capabilities.mode", true, "INVALID_ACTION"}, {onOff, true, "DEVICE_UNREACHABLE"}}
	p.err = errors.New("broker rejected")
	for _, tt := range tests {
		e := r.Act(context.Background(), "1", "lamp", tt.typ, State{Instance: "on", Value: tt.value})
		if errorResult(e)["error_code"] != tt.err {
			t.Fatal(tt, e)
		}
	}
	p.online.Store(false)
	w := request(t, s, "POST", "/provider/v1.0/user/devices/action", tok.AccessToken, `{"payload":{"devices":[{"id":"lamp","capabilities":[{"type":"`+onOff+`","state":{"instance":"on","value":true}}]}]}}`)
	if !strings.Contains(w.Body.String(), "DEVICE_UNREACHABLE") || strings.Contains(w.Body.String(), "DONE") {
		t.Fatal(w.Body.String())
	}
	for _, body := range []string{`{`, `{}`, `{"devices":null}`, `{"devices":[{}]}`, `{"devices":[]} {}`} {
		w = request(t, s, "POST", "/provider/v1.0/user/devices/query", tok.AccessToken, body)
		if w.Code != 400 {
			t.Fatalf("body=%s code=%d", body, w.Code)
		}
	}
}
func TestCommandConfirmationAndDeadline(t *testing.T) {
	c := testConfig(t)
	c.Devices[0].MQTT[0].ConfirmTimeoutMS = 30
	p := &fakePublisher{}
	p.online.Store(true)
	r := NewRegistry(c, p)
	// A stale matching cache is insufficient: a fresh MQTT update is required.
	r.Update("home/Lamp/state", []byte("1"))
	if e := r.Act(context.Background(), "1", "lamp", onOff, State{Instance: "on", Value: true}); e == nil {
		t.Fatal("stale state used as command confirmation")
	}
	p.hook = func(_ string, b []byte) { r.Update("home/Lamp/state", b) }
	if e := r.Act(context.Background(), "1", "lamp", onOff, State{Instance: "on", Value: false}); e != nil {
		t.Fatal("fast echo missed", e)
	}
	r.devices["lamp"].command <- struct{}{}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	if e := r.Act(ctx, "1", "lamp", onOff, State{Instance: "on", Value: true}); e == nil {
		t.Fatal("busy deadline ignored")
	}
	<-r.devices["lamp"].command
}
func TestRangeRelativeModeColorAndEvents(t *testing.T) {
	c := testConfig(t)
	d := &c.Devices[0]
	d.Capabilities = append(d.Capabilities, Feature{Type: "devices.capabilities.range", Retrievable: true, Parameters: map[string]any{"instance": "brightness", "range": map[string]any{"min": float64(0), "max": float64(100), "precision": float64(1)}}}, Feature{Type: "devices.capabilities.mode", Parameters: map[string]any{"instance": "fan_speed", "modes": []any{map[string]any{"value": "low"}, map[string]any{"value": "high"}}}}, Feature{Type: "devices.capabilities.color_setting", Parameters: map[string]any{"color_model": "hsv"}})
	d.Properties = []Feature{{Type: "devices.properties.event", Reportable: true, Parameters: map[string]any{"instance": "motion", "events": []any{map[string]any{"value": "detected"}, map[string]any{"value": "not_detected"}}}}}
	d.MQTT = append(d.MQTT, Binding{Instance: "brightness", State: "brightness", Set: "brightness/set"}, Binding{Instance: "fan_speed", Set: "fan/set"}, Binding{Instance: "hsv", State: "color", Set: "color/set"}, Binding{Instance: "motion", State: "motion"})
	if e := c.Validate(); e != nil {
		t.Fatal(e)
	}
	p := &fakePublisher{}
	p.online.Store(true)
	r := NewRegistry(c, p)
	r.Update("brightness", []byte("50"))
	if e := r.Act(context.Background(), "1", "lamp", "devices.capabilities.range", State{Instance: "brightness", Value: float64(10), Relative: true}); e != nil {
		t.Fatal(e)
	}
	if p.messages[0] != "brightness/set=60" {
		t.Fatal(p.messages)
	}
	for _, value := range []any{float64(101), float64(2.5), "50"} {
		if e := r.Act(context.Background(), "1", "lamp", "devices.capabilities.range", State{Instance: "brightness", Value: value}); e == nil {
			t.Fatal("invalid range accepted", value)
		}
	}
	if e := r.Act(context.Background(), "1", "lamp", "devices.capabilities.mode", State{Instance: "fan_speed", Value: "bad"}); e == nil {
		t.Fatal("invalid mode accepted")
	}
	if e := r.Act(context.Background(), "1", "lamp", "devices.capabilities.color_setting", State{Instance: "hsv", Value: map[string]any{"h": float64(120), "s": float64(50), "v": float64(100)}}); e != nil {
		t.Fatal(e)
	}
	if es := r.Update("color", []byte(`{"h":120,"s":50,"v":100}`)); len(es) > 0 {
		t.Fatal(es)
	}
	callbacks := 0
	r.OnChange = func(c Change) {
		if len(c.Properties) > 0 {
			callbacks++
		}
	}
	r.Update("motion", []byte("detected"))
	r.Update("motion", []byte("detected"))
	if callbacks != 2 {
		t.Fatal("repeated event lost")
	}
	f := Feature{Type: "devices.properties.float", Parameters: map[string]any{"instance": "temperature"}}
	for _, bad := range []string{"22junk", "NaN", "Inf", ""} {
		if _, e := normalize(f, "temperature", bad, false); e == nil {
			t.Fatal("invalid numeric accepted", bad)
		}
	}
}
func TestOAuthCodeFlowCSRFReplayRefreshAndPersistence(t *testing.T) {
	s, _, _ := fixture(t)
	w := request(t, s, "GET", "/login?return_to="+url.QueryEscape("/account"), "", "")
	cookies := w.Result().Cookies()
	csrf := regexp.MustCompile(`name="csrf" value="([^"]+)"`).FindStringSubmatch(w.Body.String())[1]
	login := httptest.NewRequest("POST", "/login", strings.NewReader(url.Values{"csrf": {csrf}, "username": {"alice"}, "password": {"test-password"}, "return_to": {"/account"}}.Encode()))
	login.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	login.AddCookie(cookies[0])
	w = httptest.NewRecorder()
	s.Handler().ServeHTTP(w, login)
	if w.Code != 303 {
		t.Fatal(w.Code, w.Body.String())
	}
	sessionCookie := w.Result().Cookies()[0]
	verifier := strings.Repeat("a", 50)
	q := url.Values{"client_id": {"yandex-client"}, "redirect_uri": {"https://social.yandex.net/broker/redirect"}, "response_type": {"code"}, "state": {"original-state"}, "scope": {"home"}, "code_challenge": {pkceHash(verifier)}, "code_challenge_method": {"S256"}}
	auth := httptest.NewRequest("GET", "/dialog/authorize?"+q.Encode(), nil)
	auth.AddCookie(sessionCookie)
	w = httptest.NewRecorder()
	s.Handler().ServeHTTP(w, auth)
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	tx := regexp.MustCompile(`name="transaction_id" value="([^"]+)"`).FindStringSubmatch(w.Body.String())[1]
	csrf = regexp.MustCompile(`name="csrf" value="([^"]+)"`).FindStringSubmatch(w.Body.String())[1]
	decision := httptest.NewRequest("POST", "/dialog/authorize/decision", strings.NewReader(url.Values{"csrf": {csrf}, "transaction_id": {tx}, "approve": {"yes"}}.Encode()))
	decision.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	decision.AddCookie(sessionCookie)
	w = httptest.NewRecorder()
	s.Handler().ServeHTTP(w, decision)
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	link := regexp.MustCompile(`href="([^"]+)"`).FindStringSubmatch(w.Body.String())
	if len(link) != 2 {
		t.Fatal("OAuth return link missing")
	}
	loc, _ := url.Parse(html.UnescapeString(link[1]))
	if loc.Query().Get("state") != "original-state" || loc.Query().Get("client_id") != "yandex-client" {
		t.Fatal("OAuth values lost")
	}
	code := loc.Query().Get("code")
	form := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {"https://social.yandex.net/broker/redirect"}, "code_verifier": {verifier}}
	send := func(v url.Values) *httptest.ResponseRecorder {
		r := httptest.NewRequest("POST", "/oauth/token", strings.NewReader(v.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.SetBasicAuth("yandex-client", "client-secret")
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, r)
		return w
	}
	form.Set("code_verifier", "wrong")
	if w = send(form); w.Code != 400 {
		t.Fatal("PKCE mismatch accepted")
	}
	form.Set("code_verifier", verifier)
	w = send(form)
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	var tok TokenResponse
	json.Unmarshal(w.Body.Bytes(), &tok)
	if w = send(form); w.Code != 400 {
		t.Fatal("authorization code reused")
	}
	if w = request(t, s, "GET", "/api/userinfo", tok.AccessToken, ""); w.Code != 200 {
		t.Fatal(w.Code)
	}
	disk, e := os.ReadFile(s.Config.DataFile)
	if e != nil {
		t.Fatal(e)
	}
	if bytes.Contains(disk, []byte(tok.AccessToken)) || bytes.Contains(disk, []byte(tok.RefreshToken)) {
		t.Fatal("raw token saved")
	}
	st, e := OpenStore(s.Config.DataFile)
	if e != nil {
		t.Fatal(e)
	}
	if _, ok := st.Find(tok.AccessToken); !ok {
		t.Fatal("token lost on restart")
	}
	if info, e := os.Stat(s.Config.DataFile); e != nil || info.Mode().Perm() != 0600 {
		t.Fatal("incorrect token store mode")
	}
	refresh := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {tok.RefreshToken}}
	w = send(refresh)
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	var lost TokenResponse
	json.Unmarshal(w.Body.Bytes(), &lost)
	// 1.2.2: a duplicate refresh returns the same pair; delayed responses
	// remain usable regardless of arrival order.
	if w = send(refresh); w.Code != 200 {
		t.Fatal("refresh retry rejected", w.Code)
	}
	var next TokenResponse
	json.Unmarshal(w.Body.Bytes(), &next)
	if next.AccessToken != lost.AccessToken || next.RefreshToken != lost.RefreshToken {
		t.Fatal("duplicate refresh changed the pair")
	}
	if _, ok := s.Store.Find(lost.AccessToken); !ok {
		t.Fatal("delayed response no longer valid")
	}
	if _, ok := s.Store.Find(tok.AccessToken); ok {
		t.Fatal("rotated access token still valid")
	}
	if w = request(t, s, "POST", "/provider/v1.0/user/unlink", next.AccessToken, ""); w.Code != 200 {
		t.Fatal(w.Code)
	}
	if w = request(t, s, "GET", "/api/userinfo", next.AccessToken, ""); w.Code != 401 {
		t.Fatal("unlink did not revoke access")
	}
	if _, e = s.Store.Refresh(next.RefreshToken, "yandex-client", s.Config.OAuth); e == nil {
		t.Fatal("unlink did not revoke refresh")
	}
	if _, e = s.Store.Refresh(tok.RefreshToken, "yandex-client", s.Config.OAuth); e == nil {
		t.Fatal("unlink did not revoke retry window")
	}
}
func TestOAuthRedirectInvalidCodeExpiryAndClientSeparation(t *testing.T) {
	s, _, _ := fixture(t)
	w := request(t, s, "GET", "/dialog/authorize?client_id=yandex-client&response_type=code&redirect_uri=https://evil.example/cb", "", "")
	if w.Code != 400 || w.Header().Get("Location") != "" {
		t.Fatal("unregistered redirect accepted")
	}
	for _, code := range []string{"unknown", "expired", "another-client"} {
		s.codes[hashToken(code)] = authorization{ClientID: "yandex-client", UserID: "1", Redirect: "https://social.yandex.net/broker/redirect", Expires: time.Now().Add(time.Minute)}
		if code == "unknown" {
			delete(s.codes, hashToken(code))
		}
		if code == "expired" {
			v := s.codes[hashToken(code)]
			v.Expires = time.Now().Add(-time.Second)
			s.codes[hashToken(code)] = v
		}
		client := "yandex-client"
		secret := "client-secret"
		if code == "another-client" {
			client = "other-client"
			secret = "other-secret"
		}
		r := httptest.NewRequest("POST", "/oauth/token", strings.NewReader(url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {"https://social.yandex.net/broker/redirect"}}.Encode()))
		r.SetBasicAuth(client, secret)
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w = httptest.NewRecorder()
		s.Handler().ServeHTTP(w, r)
		if w.Code != 400 {
			t.Fatal(code, w.Code)
		}
	}
	a := issue(t, s, "1", "yandex-client")
	b := issue(t, s, "1", "other-client")
	if _, ok := s.Store.Find(a.AccessToken); !ok {
		t.Fatal("second client erased first token")
	}
	if e := s.Store.Revoke("1", "yandex-client"); e != nil {
		t.Fatal(e)
	}
	if _, ok := s.Store.Find(b.AccessToken); !ok {
		t.Fatal("unlink revoked another client")
	}
	app := issue(t, s, "", "yandex-client")
	if w = request(t, s, "GET", "/provider/v1.0/user/devices", app.AccessToken, ""); w.Code != 401 {
		t.Fatal("client-only token accessed devices")
	}
	if w = request(t, s, "GET", "/api/clientinfo", app.AccessToken, ""); w.Code != 200 {
		t.Fatal(w.Code)
	}
}
func TestCallbackACLReportableRetryAndUnlink(t *testing.T) {
	s, r, _ := fixture(t)
	issue(t, s, "1", "yandex-client")
	issue(t, s, "2", "yandex-client")
	calls := 0
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		calls++
		if req.Header.Get("Authorization") != "OAuth notification-secret" {
			t.Error("wrong callback authorization")
		}
		var body map[string]any
		json.NewDecoder(req.Body).Decode(&body)
		if body["payload"].(map[string]any)["user_id"] != "1" {
			t.Error("callback sent to user without access")
		}
		if calls == 1 {
			w.WriteHeader(503)
		} else {
			w.WriteHeader(202)
			io.WriteString(w, `{"request_id":"callback-test","status":"ok"}`)
		}
	}))
	defer target.Close()
	n := NewNotifier([]NotificationConfig{{SkillID: "skill", Token: "notification-secret", UserID: "1", ClientID: "yandex-client"}, {SkillID: "skill", Token: "notification-secret", UserID: "2", ClientID: "yandex-client"}}, r, s.Store, s.Log)
	n.BaseURL = target.URL
	r.OnChange = n.Enqueue
	r.Update("home/Lamp/state", []byte("1"))
	if len(n.jobs) != 1 {
		t.Fatal("callback ACL ignored")
	}
	job := <-n.jobs
	n.send(context.Background(), job)
	if calls != 2 {
		t.Fatal("5xx was not retried")
	}
	if e := s.Store.Revoke("1", "yandex-client"); e != nil {
		t.Fatal(e)
	}
	n.send(context.Background(), job)
	if calls != 2 {
		t.Fatal("callback sent after unlink")
	}
	r.Update("home/Lamp/state", []byte("0"))
	if len(n.jobs) != 0 {
		t.Fatal("notification queued for unlinked user")
	}
}
func TestStoreConcurrentRefreshAndWriteFailure(t *testing.T) {
	s, _, _ := fixture(t)
	tok := issue(t, s, "1", "yandex-client")
	// 1.2.2: all concurrent duplicates get the same persisted live pair.
	var mu sync.Mutex
	issued := []TokenResponse{}
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if r, e := s.Store.Refresh(tok.RefreshToken, "yandex-client", s.Config.OAuth); e == nil {
				mu.Lock()
				issued = append(issued, r)
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if len(issued) != 8 {
		t.Fatal("refresh retry rejected", len(issued))
	}
	for _, r := range issued {
		if r.AccessToken != issued[0].AccessToken || r.RefreshToken != issued[0].RefreshToken {
			t.Fatal("concurrent retry changed the pair")
		}
		if _, ok := s.Store.Find(r.AccessToken); !ok {
			t.Fatal("concurrent response invalid")
		}
	}
	blocked := filepath.Join(t.TempDir(), "file")
	os.WriteFile(blocked, []byte("blocked"), 0600)
	st := &Store{path: filepath.Join(blocked, "tokens.json")}
	if _, e := st.Issue("1", "yandex-client", "", s.Config.OAuth); e == nil {
		t.Fatal("failed storage returned token")
	}
	if len(st.tokens) != 0 {
		t.Fatal("failed write committed an in-memory token")
	}
}
func TestConfigValidationAndMigration(t *testing.T) {
	c := testConfig(t)
	bad := c
	bad.Devices = append([]DeviceConfig{}, c.Devices...)
	bad.Devices = append(bad.Devices, c.Devices[0])
	if bad.Validate() == nil {
		t.Fatal("duplicate id accepted")
	}
	bad = c
	bad.Clients = append([]Client{}, c.Clients...)
	bad.Clients[0].RedirectURIs = []string{"https://example.org/cb#bad"}
	if bad.Validate() == nil {
		t.Fatal("redirect fragment accepted")
	}
	c.Users[0].PasswordHash = ""
	c.Users[0].Password = "legacy-password"
	c.Clients[0].RedirectURIs = nil
	dir := t.TempDir()
	legacy := filepath.Join(dir, "legacy.json")
	output := filepath.Join(dir, "config.json")
	b, _ := json.Marshal(c)
	os.WriteFile(legacy, b, 0600)
	if e := Migrate(legacy, output); e != nil {
		t.Fatal(e)
	}
	m, e := LoadConfig(output)
	if e != nil {
		t.Fatal(e)
	}
	if m.Users[0].Password != "" || bcrypt.CompareHashAndPassword([]byte(m.Users[0].PasswordHash), []byte("legacy-password")) != nil {
		t.Fatal("password migration failed")
	}
	if e = Migrate(legacy, output); e == nil {
		t.Fatal("migration overwrote existing file")
	}
}
func TestConcurrentStateAndQuery(t *testing.T) {
	_, r, _ := fixture(t)
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for n := 0; n < 100; n++ {
				r.Update("home/Lamp/state", []byte("1"))
				r.Query("1", "lamp")
			}
		}()
	}
	wg.Wait()
}
