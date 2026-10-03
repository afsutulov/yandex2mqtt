package bridge

// Проблемы, найденные при проверке версии 1.2.0 (см. REVIEW-1.2.1.ru.md).

import (
	"context"
	"io"
	"log/slog"
	"net/http/httptest"
	"strings"
	"testing"
)

// П1. Диапазон без state-топика объявляется retrievable=false. Для таких
// функций Яндекс отправляет «громче/ярче» как relative-команду, а 1.2.0
// всегда отвечал DEVICE_UNREACHABLE «current state is unknown».
func TestCommandOnlyRelativeRangeUsesLastCommand(t *testing.T) {
	c := testConfig(t)
	d := &c.Devices[0]
	d.Capabilities = append(d.Capabilities, Feature{Type: "devices.capabilities.range", Retrievable: true, Parameters: map[string]any{"instance": "volume", "range": map[string]any{"min": float64(0), "max": float64(100), "precision": float64(1)}}})
	d.MQTT = append(d.MQTT, Binding{Instance: "volume", Set: "tv/volume/set"})
	if e := c.Validate(); e != nil {
		t.Fatal(e)
	}
	p := &fakePublisher{}
	p.online.Store(true)
	r := NewRegistry(c, p)
	rel := State{Instance: "volume", Value: float64(10), Relative: true}
	// Без единой абсолютной команды базы нет: ошибка остаётся честной.
	if e := r.Act(context.Background(), "1", "lamp", "devices.capabilities.range", rel); e == nil {
		t.Fatal("relative command without any known base accepted")
	}
	if e := r.Act(context.Background(), "1", "lamp", "devices.capabilities.range", State{Instance: "volume", Value: float64(30)}); e != nil {
		t.Fatal(e)
	}
	if e := r.Act(context.Background(), "1", "lamp", "devices.capabilities.range", rel); e != nil {
		t.Fatalf("relative command after an absolute one failed: %v", e)
	}
	if last := p.messages[len(p.messages)-1]; last != "tv/volume/set=40" {
		t.Fatal(last)
	}
	// Последняя команда не выдаётся как состояние: функция остаётся без обратной связи.
	caps, _ := r.Query("1", "lamp")["capabilities"].([]map[string]any)
	for _, f := range caps {
		if f["type"] == "devices.capabilities.range" {
			t.Fatal("command echoed as state")
		}
	}
}

// П2. Ротация refresh-токена без окна повтора: если ответ на refresh потерян
// (обрыв сети, тайм-аут прокси), Яндекс повторяет запрос со старым токеном,
// получает invalid_grant, и привязка аккаунта ломается до ручной перепривязки.
func TestRefreshRetryWithinGraceWindow(t *testing.T) {
	c := testConfig(t)
	st, e := OpenStore(c.DataFile)
	if e != nil {
		t.Fatal(e)
	}
	first, e := st.Issue("1", "yandex-client", "", c.OAuth)
	if e != nil {
		t.Fatal(e)
	}
	lost, e := st.Refresh(first.RefreshToken, "yandex-client", c.OAuth)
	if e != nil {
		t.Fatal(e)
	}
	retry, e := st.Refresh(first.RefreshToken, "yandex-client", c.OAuth)
	if e != nil {
		t.Fatalf("retry with the previous refresh token rejected: %v", e)
	}
	if _, ok := st.Find(retry.AccessToken); !ok {
		t.Fatal("retried access token invalid")
	}
	// 1.2.2: повтор возвращает ту же пару, не аннулируя запоздавший ответ.
	if retry.AccessToken != lost.AccessToken || retry.RefreshToken != lost.RefreshToken {
		t.Fatal("duplicate refresh changed the pair")
	}
	if _, ok := st.Find(lost.AccessToken); !ok {
		t.Fatal("delayed response contains an invalid token")
	}
	// Другой клиент не может воспользоваться окном.
	if _, e := st.Refresh(first.RefreshToken, "other-client", c.OAuth); e == nil {
		t.Fatal("grace window ignored client binding")
	}
	// Окно переживает перезапуск процесса.
	st2, e := OpenStore(c.DataFile)
	if e != nil {
		t.Fatal(e)
	}
	if _, e := st2.Refresh(first.RefreshToken, "yandex-client", c.OAuth); e != nil {
		t.Fatalf("grace window lost after restart: %v", e)
	}
	// После окна старый токен отклоняется.
	for i := range st2.tokens {
		st2.tokens[i].PrevRefreshExpires = 1
	}
	if _, e := st2.Refresh(first.RefreshToken, "yandex-client", c.OAuth); e == nil {
		t.Fatal("previous refresh token accepted after the grace window")
	}
}

// П3. Таблица лимитов заполнялась 10000 ключами с разных адресов одной IPv6 /64
// (у любого клиента IPv6 их 2^64), после чего форма входа отвечала 429 всем.
func TestIPv6PrefixCannotExhaustRateTable(t *testing.T) {
	s, _, _ := fixture(t)
	h := s.Handler()
	post := func(remote string) int {
		r := httptest.NewRequest("POST", "/login", strings.NewReader("username=x&password=y&csrf=z"))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.RemoteAddr = remote
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w.Code
	}
	for i := 0; i < 10050; i++ {
		post("[2001:db8::" + strings.ToLower(hex4(i)) + "]:1234")
	}
	if post("198.51.100.7:1234") == 429 {
		t.Fatal("unrelated client locked out by one IPv6 /64")
	}
	if post("[2001:db8::ffff]:1") != 429 {
		t.Fatal("the attacking /64 is not limited")
	}
	_ = slog.New(slog.NewTextHandler(io.Discard, nil))
}

func hex4(i int) string {
	const digits = "0123456789abcdef"
	return string([]byte{digits[i>>12&15], digits[i>>8&15], digits[i>>4&15], digits[i&15]})
}
