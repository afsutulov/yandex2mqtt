package bridge

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func regressionRegistry(t *testing.T, c Config) (*Registry, *fakePublisher) {
	t.Helper()
	p := &fakePublisher{}
	p.online.Store(true)
	return NewRegistry(c, p), p
}
func TestRegression01CommandOnly(t *testing.T) {
	c := testConfig(t)
	c.Devices[0].MQTT[0].State = ""
	r, p := regressionRegistry(t, c)
	if q := r.Query("1", "lamp"); q["error_code"] != nil {
		t.Fatal(q)
	}
	cap := r.Discovery("1")[0]["capabilities"].([]map[string]any)[0]
	if cap["retrievable"] != false || cap["reportable"] != false {
		t.Fatal(cap)
	}
	if e := r.Act(context.Background(), "1", "lamp", onOff, State{Instance: "on", Value: true}); e != nil || p.count() != 1 {
		t.Fatal(e, p.count())
	}
}
func TestRegression02PartialState(t *testing.T) {
	c := testConfig(t)
	c.Devices[0].Properties = []Feature{{Type: "devices.properties.float", Retrievable: true, Parameters: map[string]any{"instance": "temperature"}}}
	c.Devices[0].MQTT = append(c.Devices[0].MQTT, Binding{Instance: "temperature", State: "temperature"})
	r, _ := regressionRegistry(t, c)
	r.Update("home/Lamp/state", []byte("1"))
	q := r.Query("1", "lamp")
	if q["error_code"] != nil || len(q["capabilities"].([]map[string]any)) != 1 {
		t.Fatal(q)
	}
}
func TestRegression03RangeTelemetry(t *testing.T) {
	f := Feature{Type: "devices.capabilities.range", Parameters: map[string]any{"instance": "brightness", "range": map[string]any{"min": float64(1), "max": float64(100), "precision": float64(1)}}}
	for _, n := range []float64{0, 22.3, 101} {
		if _, e := normalize(f, "brightness", n, false); e != nil {
			t.Error(n, e)
		}
		if _, e := normalize(f, "brightness", n, true); e == nil {
			t.Error("invalid command accepted", n)
		}
	}
}
func TestRegression04ParallelActions(t *testing.T) {
	c := testConfig(t)
	c.Devices = nil
	for i := 0; i < 5; i++ {
		d := testConfig(t).Devices[0]
		d.ID = fmt.Sprint(i)
		d.MQTT = []Binding{{Instance: "on", Set: d.ID + "/set", State: d.ID + "/state", ConfirmTimeoutMS: 1500}}
		c.Devices = append(c.Devices, d)
	}
	r, p := regressionRegistry(t, c)
	var wg sync.WaitGroup
	p.hook = func(topic string, b []byte) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			time.Sleep(900 * time.Millisecond)
			r.Update(strings.TrimSuffix(topic, "/set")+"/state", b)
		}()
	}
	defer wg.Wait()
	st, e := OpenStore(c.DataFile)
	if e != nil {
		t.Fatal(e)
	}
	s, e := NewServer(c, r, st, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if e != nil {
		t.Fatal(e)
	}
	ds := []any{}
	for _, d := range c.Devices {
		ds = append(ds, map[string]any{"id": d.ID, "capabilities": []any{map[string]any{"type": onOff, "state": State{Instance: "on", Value: true}}}})
	}
	b, _ := json.Marshal(map[string]any{"payload": map[string]any{"devices": ds}})
	tok := issue(t, s, "1", "yandex-client")
	w := request(t, s, "POST", "/v1.0/user/devices/action", tok.AccessToken, string(b))
	if p.count() != 5 || strings.Contains(w.Body.String(), "ERROR") {
		t.Fatal(p.count(), w.Body.String())
	}
}
func TestRegression05HeadProbe(t *testing.T) {
	s, _, _ := fixture(t)
	for _, path := range []string{"/v1.0", "/provider/v1.0", "/provider"} {
		w := request(t, s, "HEAD", path, "", "")
		if w.Code != 200 || w.Body.Len() != 0 {
			t.Error(path, w.Code, w.Body.String())
		}
	}
	if request(t, s, "GET", "/v1.0/user/devices", "", "").Code != 401 {
		t.Fatal("missing bearer accepted")
	}
}
func TestRegression06RedirectCSP(t *testing.T) {
	s, _, _ := fixture(t)
	w := request(t, s, "GET", "/login", "", "")
	csp := w.Header().Get("Content-Security-Policy")
	if !strings.Contains(csp, "form-action 'self' https://social.yandex.net") {
		t.Fatal(csp)
	}
	if strings.Contains(csp, "form-action *") {
		t.Fatal("wildcard CSP")
	}
}
func TestRegression07AnonymousSessions(t *testing.T) {
	s, _, _ := fixture(t)
	for i := 0; i < 1000; i++ {
		if w := request(t, s, "GET", "/login", "", ""); w.Code != 200 {
			t.Fatal(w.Code)
		}
	}
	if len(s.sessions) != 0 {
		t.Fatal("anonymous sessions retained", len(s.sessions))
	}
}
func TestRegression08RateIsolation(t *testing.T) {
	s, _, _ := fixture(t)
	tok := issue(t, s, "1", "yandex-client")
	for i := 0; i < 32; i++ {
		request(t, s, "POST", "/login", "", "")
	}
	form := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {tok.RefreshToken}, "client_id": {"yandex-client"}, "client_secret": {"client-secret"}}
	r := httptest.NewRequest("POST", "/oauth/token", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
}
func TestRegression09BasicPlus(t *testing.T) {
	s, _, _ := fixture(t)
	s.Config.Clients[0].Secret = "abc+def%ghi"
	s.Config.OAuth.AllowClientCredentials = true
	for _, secret := range []string{"abc+def%ghi", url.QueryEscape("abc+def%ghi")} {
		r := httptest.NewRequest("POST", "/oauth/token", strings.NewReader("grant_type=client_credentials"))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.SetBasicAuth("yandex-client", secret)
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, r)
		if w.Code != 200 {
			t.Error(secret, w.Code, w.Body.String())
		}
	}
}
func TestRegression10TLSListen(t *testing.T) {
	c := Config{HTTPS: HTTPSConfig{Certificate: "cert.pem", PrivateKey: "key.pem"}}
	c.Defaults()
	if c.HTTP.Listen != "0.0.0.0:4433" {
		t.Fatal(c.HTTP.Listen)
	}
	c = Config{HTTP: HTTPConfig{Listen: "127.0.0.1:9999"}, HTTPS: HTTPSConfig{Certificate: "cert.pem"}}
	c.Defaults()
	if c.HTTP.Listen != "127.0.0.1:9999" {
		t.Fatal(c.HTTP.Listen)
	}
}
func TestRegression12StrictDeviceFiles(t *testing.T) {
	for _, array := range []bool{false, true} {
		for _, field := range []string{"device", "feature", "binding"} {
			t.Run(fmt.Sprintf("%t/%s", array, field), func(t *testing.T) {
				c := testConfig(t)
				d := c.Devices[0]
				c.Devices = nil
				dir := t.TempDir()
				c.DevicesDir = "devices"
				if e := os.Mkdir(filepath.Join(dir, "devices"), 0700); e != nil {
					t.Fatal(e)
				}
				b, _ := json.Marshal(d)
				text := string(b)
				switch field {
				case "device":
					text = strings.Replace(text, `"mqtt":`, `"descriptionn":"typo","mqtt":`, 1)
				case "feature":
					text = strings.Replace(text, `"retrievable":`, `"retrievabl":`, 1)
				case "binding":
					text = strings.Replace(text, `"instance":"on"`, `"confirmTimeoutMss":123,"instance":"on"`, 1)
				}
				if array {
					text = "[" + text + "]"
				}
				if e := os.WriteFile(filepath.Join(dir, "devices", "lamp.json"), []byte(text), 0600); e != nil {
					t.Fatal(e)
				}
				b, _ = json.Marshal(c)
				path := filepath.Join(dir, "config.json")
				if e := os.WriteFile(path, b, 0600); e != nil {
					t.Fatal(e)
				}
				if _, e := LoadConfig(path); e == nil || !strings.Contains(e.Error(), "unknown field") {
					t.Fatal("unknown field not rejected", e)
				}
			})
		}
	}
}

func TestSignedLoginChallengeRejectsTampering(t *testing.T) {
	s, _, _ := fixture(t)
	w := request(t, s, "GET", "/login", "", "")
	cookie := w.Result().Cookies()[0]
	parts := strings.Split(cookie.Value, ".")
	parts[0] = strings.Repeat("a", 43)
	cookie.Value = strings.Join(parts, ".")
	form := url.Values{"csrf": {cookie.Value}, "username": {"alice"}, "password": {"test-password"}}
	r := httptest.NewRequest("POST", "/login", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.AddCookie(cookie)
	w = httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != 403 || len(s.sessions) != 0 {
		t.Fatal(w.Code, "forged CSRF accepted")
	}
}
func TestTrustedProxyRateLimits(t *testing.T) {
	c := testConfig(t)
	c.HTTP.TrustedProxies = []string{"127.0.0.1/32"}
	reg, _ := regressionRegistry(t, c)
	st, e := OpenStore(c.DataFile)
	if e != nil {
		t.Fatal(e)
	}
	s, e := NewServer(c, reg, st, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if e != nil {
		t.Fatal(e)
	}
	attempt := func(peer, forwarded string) int {
		r := httptest.NewRequest("POST", "/login", nil)
		r.RemoteAddr = peer
		r.Header.Set("X-Forwarded-For", forwarded)
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, r)
		return w.Code
	}
	for i := 0; i < 30; i++ {
		if code := attempt("127.0.0.1:1234", "198.51.100.1"); code != 403 {
			t.Fatal(code)
		}
	}
	if attempt("127.0.0.1:1234", "198.51.100.1") != 429 || attempt("127.0.0.1:1234", "198.51.100.2") != 403 {
		t.Fatal("trusted proxy identities not isolated")
	}
	for i := 0; i < 31; i++ {
		attempt("203.0.113.1:1234", "198.51.100.3")
	}
	if attempt("203.0.113.1:1234", "198.51.100.4") != 429 {
		t.Fatal("untrusted forwarded header bypassed limit")
	}
}
func TestConfirmationIgnoresUnrelatedState(t *testing.T) {
	c := testConfig(t)
	c.Devices[0].Properties = []Feature{{Type: "devices.properties.float", Parameters: map[string]any{"instance": "temperature"}}}
	c.Devices[0].MQTT = append(c.Devices[0].MQTT, Binding{Instance: "temperature", State: "temperature"})
	c.Devices[0].MQTT[0].ConfirmTimeoutMS = 100
	r, p := regressionRegistry(t, c)
	r.Update("home/Lamp/state", []byte("1"))
	p.hook = func(string, []byte) { r.Update("temperature", []byte("22")) }
	if e := r.Act(context.Background(), "1", "lamp", onOff, State{Instance: "on", Value: true}); e == nil {
		t.Fatal("unrelated measurement confirmed stale target state")
	}
}
func TestDuplicateDeviceActionOrder(t *testing.T) {
	s, r, p := fixture(t)
	p.hook = func(topic string, b []byte) { r.Update("home/Lamp/state", b) }
	tok := issue(t, s, "1", "yandex-client")
	w := request(t, s, "POST", "/v1.0/user/devices/action", tok.AccessToken, `{"payload":{"devices":[{"id":"lamp","capabilities":[{"type":"devices.capabilities.on_off","state":{"instance":"on","value":true}}]},{"id":"lamp","capabilities":[{"type":"devices.capabilities.on_off","state":{"instance":"on","value":false}}]}]}}`)
	if strings.Contains(w.Body.String(), "ERROR") || p.count() != 2 {
		t.Fatal(w.Body.String())
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.messages[0] != "home/lamp/set=1" || p.messages[1] != "home/lamp/set=0" {
		t.Fatal(p.messages)
	}
}
