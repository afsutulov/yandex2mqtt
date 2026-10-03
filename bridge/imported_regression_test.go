package bridge

// Imported from the user's 1.0.1 archive. Four assertions are intentionally
// adapted to the merged policy: command-only state is not fabricated, incoming
// telemetry is not clamped, proxy trust is explicit, TLS is compared semantically.
// Original input SHA-256 and the decisions are documented in MERGE.ru.md.

import (
	"context"
	"encoding/base64"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	broker "github.com/mochi-mqtt/server/v2"
	"github.com/mochi-mqtt/server/v2/hooks/auth"
	"github.com/mochi-mqtt/server/v2/listeners"
)

// R1. Функция без state-топика (только set) — типичный
// конфиг оригинала. В 1.0.0 query навсегда возвращал DEVICE_UNREACHABLE.
func TestImportedWriteOnlyCapabilityIsControllable(t *testing.T) {
	c := testConfig(t)
	c.Devices[0].MQTT[0].State = ""
	if e := c.Validate(); e != nil {
		t.Fatal(e)
	}
	p := &fakePublisher{}
	p.online.Store(true)
	r := NewRegistry(c, p)
	if e := r.Act(context.Background(), "1", "lamp", onOff, State{Instance: "on", Value: true}); e != nil {
		t.Fatal(e)
	}
	m := r.Query("1", "lamp")
	if m["error_code"] != nil {
		t.Fatalf("write-only device reported as unreachable: %v", m)
	}
	caps := m["capabilities"].([]map[string]any)
	if len(caps) != 0 {
		t.Fatal("command-only state must remain unobserved", caps)
	}
	cap := r.Discovery("1")[0]["capabilities"].([]map[string]any)[0]
	if cap["retrievable"] != false {
		t.Fatal(cap)
	}
}

// R2. Одна неизвестная функция не должна делать недоступным всё устройство,
// если другие функции уже имеют состояние.
func TestPartialStateDoesNotHideKnownStates(t *testing.T) {
	c := testConfig(t)
	d := &c.Devices[0]
	d.Properties = []Feature{{Type: "devices.properties.float", Retrievable: true, Parameters: map[string]any{"instance": "power"}}}
	d.MQTT = append(d.MQTT, Binding{Instance: "power", State: "power"})
	if e := c.Validate(); e != nil {
		t.Fatal(e)
	}
	p := &fakePublisher{}
	p.online.Store(true)
	r := NewRegistry(c, p)
	r.Update("home/Lamp/state", []byte("1"))
	m := r.Query("1", "lamp")
	if m["error_code"] != nil {
		t.Fatalf("known on_off state hidden: %v", m)
	}
	if len(m["capabilities"].([]map[string]any)) != 1 || len(m["properties"].([]map[string]any)) != 0 {
		t.Fatalf("unexpected query result: %v", m)
	}
}

// R3. Входящее MQTT-состояние сохраняется без подмены, включая вне min/max/precision.
// В версии 1.0.0 такие значения
// (яркость 0 при min=1, уставка 22.3 при precision 1) отбрасывалось целиком.
func TestImportedRangeStateFromMQTTIsPreserved(t *testing.T) {
	c := testConfig(t)
	d := &c.Devices[0]
	d.Capabilities = append(d.Capabilities, Feature{Type: "devices.capabilities.range", Retrievable: true, Parameters: map[string]any{"instance": "brightness", "range": map[string]any{"min": float64(1), "max": float64(100), "precision": float64(1)}}})
	d.MQTT = append(d.MQTT, Binding{Instance: "brightness", State: "brightness", Set: "brightness/set"})
	if e := c.Validate(); e != nil {
		t.Fatal(e)
	}
	p := &fakePublisher{}
	p.online.Store(true)
	r := NewRegistry(c, p)
	for payload, want := range map[string]float64{"0": 0, "37.5": 37.5, "255": 255} {
		if es := r.Update("brightness", []byte(payload)); len(es) > 0 {
			t.Fatalf("state %s rejected: %v", payload, es)
		}
		r.devices["lamp"].mu.RLock()
		got := r.devices["lamp"].values[featureKey("devices.capabilities.range", "brightness")]
		r.devices["lamp"].mu.RUnlock()
		if got != want {
			t.Fatalf("state %s stored as %v, want %v", payload, got, want)
		}
	}
	// Относительная команда от «нестандартного» текущего значения
	// приводится к границам/сетке, а не отклоняется.
	r.Update("brightness", []byte("97.5"))
	if e := r.Act(context.Background(), "1", "lamp", "devices.capabilities.range", State{Instance: "brightness", Value: float64(10), Relative: true}); e != nil {
		t.Fatal(e)
	}
	if last := p.messages[len(p.messages)-1]; last != "brightness/set=100" {
		t.Fatal(last)
	}
}

// R4. Команды нескольким устройствам выполнялись последовательно в общем бюджете
// 3,5 с: при confirmTimeoutMs устройства из конца пакета не получали команду вовсе.
func TestActionDevicesRunInParallel(t *testing.T) {
	c := testConfig(t)
	base := c.Devices[0]
	c.Devices = nil
	for _, id := range []string{"a", "b", "c", "d", "e"} {
		d := base
		d.ID = id
		d.ValueMapping = nil
		d.MQTT = []Binding{{Instance: "on", Set: id + "/set", State: id + "/state", ConfirmTimeoutMS: 1000}}
		c.Devices = append(c.Devices, d)
	}
	if e := c.Validate(); e != nil {
		t.Fatal(e)
	}
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
	tok := issue(t, s, "1", "yandex-client")
	body := `{"payload":{"devices":[`
	for i, id := range []string{"a", "b", "c", "d", "e"} {
		if i > 0 {
			body += ","
		}
		body += `{"id":"` + id + `","capabilities":[{"type":"` + onOff + `","state":{"instance":"on","value":true}}]}`
	}
	body += `]}}`
	start := time.Now()
	w := request(t, s, "POST", "/provider/v1.0/user/devices/action", tok.AccessToken, body)
	if p.count() != 5 {
		t.Fatalf("only %d of 5 devices received a command", p.count())
	}
	if time.Since(start) > 2500*time.Millisecond {
		t.Fatal("devices processed sequentially")
	}
	if strings.Count(w.Body.String(), `"id":"`) != 5 {
		t.Fatal(w.Body.String())
	}
}

// R5. HEAD /v1.0 — проверка доступности Endpoint URL без авторизации (протокол Яндекса).
func TestEndpointHeadCheckWithoutToken(t *testing.T) {
	s, _, _ := fixture(t)
	for _, path := range []string{"/provider/v1.0", "/provider/v1.0/", "/v1.0", "/v1.0/"} {
		w := request(t, s, "HEAD", path, "", "")
		if w.Code != 200 {
			t.Fatalf("HEAD %s: %d", path, w.Code)
		}
	}
}

// R6. CSP form-action 'self' блокирует в Chromium/WebView редирект формы согласия
// на https://social.yandex.net/... — привязка аккаунта не завершалась.
func TestCSPAllowsOAuthRedirectAfterForm(t *testing.T) {
	s, _, _ := fixture(t)
	w := request(t, s, "GET", "/login", "", "")
	csp := w.Header().Get("Content-Security-Policy")
	if !strings.Contains(csp, "form-action 'self' https://social.yandex.net") {
		t.Fatal(csp)
	}
}

// R7. Анонимные GET /login создавали 12-часовые сессии; 10000 запросов
// блокировали вход всем пользователям.
func TestLoginPageFloodDoesNotLockOut(t *testing.T) {
	s, _, _ := fixture(t)
	h := s.Handler()
	for i := 0; i < 10050; i++ {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest("GET", "/login", nil))
		if w.Code != 200 {
			t.Fatalf("login page unavailable after %d anonymous requests: %d", i, w.Code)
		}
	}
}

// R8. Лимит неудачных входов не должен блокировать обмен токенов Яндексом,
// а за обратным прокси клиентом считается X-Real-IP.
func TestRateLimitSeparatesLoginAndTokenAndHonoursProxy(t *testing.T) {
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
	h := s.Handler()
	bad := func(ip string) int {
		r := httptest.NewRequest("POST", "/login", strings.NewReader("username=x&password=y&csrf=z"))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.RemoteAddr = "127.0.0.1:5000"
		r.Header.Set("X-Real-IP", ip)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w.Code
	}
	for i := 0; i < 40; i++ {
		bad("203.0.113.9")
	}
	if bad("203.0.113.9") != 429 {
		t.Fatal("attacker not limited")
	}
	if bad("198.51.100.7") == 429 {
		t.Fatal("other client behind the proxy blocked")
	}
	form := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {"nope"}, "client_id": {"yandex-client"}, "client_secret": {"client-secret"}}
	r := httptest.NewRequest("POST", "/oauth/token", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.RemoteAddr = "127.0.0.1:5000"
	r.Header.Set("X-Real-IP", "203.0.113.9")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code == 429 {
		t.Fatal("token endpoint blocked by login failures")
	}
}

// R9. Basic-авторизация клиента с '+' в секрете без URL-кодирования.
func TestBasicAuthSecretWithPlus(t *testing.T) {
	c := testConfig(t)
	c.Clients[0].Secret = "a+b/c=="
	p := &fakePublisher{}
	r := NewRegistry(c, p)
	st, _ := OpenStore(c.DataFile)
	s, _ := NewServer(c, r, st, slog.New(slog.NewTextHandler(io.Discard, nil)))
	req := httptest.NewRequest("POST", "/oauth/token", strings.NewReader("grant_type=refresh_token&refresh_token=x"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("yandex-client:a+b/c==")))
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req)
	if w.Code == http.StatusUnauthorized {
		t.Fatal("raw Basic credentials rejected")
	}
}

// R10. Собственный TLS (как в оригинале) по умолчанию слушал 127.0.0.1 —
// Яндекс не мог подключиться.
func TestDirectTLSListensOnAllInterfaces(t *testing.T) {
	c := Config{HTTPS: HTTPSConfig{Certificate: "c.pem", PrivateKey: "k.pem", Port: 4433}}
	c.Defaults()
	if c.HTTP.Listen != "0.0.0.0:4433" {
		t.Fatal(c.HTTP.Listen)
	}
	c = Config{}
	c.Defaults()
	if c.HTTP.Listen != "127.0.0.1:8080" {
		t.Fatal(c.HTTP.Listen)
	}
}

// R11. Кратковременный разрыв MQTT стирал все известные состояния; для
// не-retained топиков устройства становились «недоступны» до следующего
// сообщения (часами). Проверяется с настоящим брокером: перезапуск брокера
// без retained-сообщения не должен терять последнее известное состояние.
func TestReconnectKeepsLastKnownState(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	start := func(addr string) (*broker.Server, string) {
		b := broker.New(&broker.Options{Logger: log, InlineClient: true})
		if e := b.AddHook(&auth.AllowHook{}, nil); e != nil {
			t.Fatal(e)
		}
		l := listeners.NewTCP(listeners.Config{ID: "tcp", Address: addr})
		if e := b.AddListener(l); e != nil {
			t.Fatal(e)
		}
		if e := b.Serve(); e != nil {
			t.Fatal(e)
		}
		return b, l.Address()
	}
	b, addr := start("127.0.0.1:0")
	c := testConfig(t)
	c.MQTT.URL = "tcp://" + addr
	c.MQTT.ClientID = "bridge-reconnect-test"
	m, e := NewMQTT(c.MQTT, log)
	if e != nil {
		t.Fatal(e)
	}
	r := NewRegistry(c, m)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	m.Start(ctx, r)
	defer m.Close()
	waitUntil(t, 4*time.Second, m.Connected)
	// Non-retained state; broker defaults differ by configuration.
	if e := b.Publish("home/Lamp/state", []byte("1"), false, 0); e != nil {
		t.Fatal(e)
	}
	waitUntil(t, 3*time.Second, func() bool { return r.Query("1", "lamp")["error_code"] == nil })
	b.Close()
	waitUntil(t, 3*time.Second, func() bool { return !m.Connected() })
	second, _ := start(addr)
	defer second.Close()
	waitUntil(t, 8*time.Second, m.Connected)
	q := r.Query("1", "lamp")
	if q["error_code"] != nil {
		t.Fatalf("state lost after reconnect: %v", q)
	}
	if q["capabilities"].([]map[string]any)[0]["state"].(map[string]any)["value"] != true {
		t.Fatal(q)
	}
}

// R12. Файлы devicesDir читались без DisallowUnknownFields, опечатка
// (например "capabilites") молча теряла функции устройства.
func TestDevicesDirIsStrict(t *testing.T) {
	dir := t.TempDir()
	cfg := `{"users":[{"id":"1","username":"a","passwordHash":"` + testConfigHash(t) + `"}],
	"clients":[{"id":"1","clientId":"c","clientSecret":"s","redirectUris":["https://social.yandex.net/broker/redirect"]}],
	"devicesDir":"dev"}`
	writeFile(t, dir+"/config.json", cfg)
	writeFile(t, dir+"/dev/x.json", `{"id":"x","name":"X","capabilites":[]}`)
	if _, e := LoadConfig(dir + "/config.json"); e == nil {
		t.Fatal("typo in device file accepted")
	}
}

func testConfigHash(t *testing.T) string { t.Helper(); testConfig(t); return testHash }
func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if e := os.MkdirAll(filepath.Dir(path), 0700); e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(path, []byte(content), 0600); e != nil {
		t.Fatal(e)
	}
}
