package bridge

// Проблемы, найденные при проверке версии 1.2.2 (см. REVIEW-1.2.3.ru.md).

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
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

// Н1. Функция без state-топика, но с явным начальным state объявляется
// retrievable=true (так рекомендует документация 1.2.x). В 1.2.2 query
// навсегда возвращал начальное значение: Алиса включила свет, а приложение
// показывает «выключен» и предлагает включить снова.
func TestExplicitStateWithoutFeedbackFollowsCommands(t *testing.T) {
	c := testConfig(t)
	c.Devices[0].MQTT[0].State = ""
	c.Devices[0].Capabilities[0].State = &State{Instance: "on", Value: false}
	if e := c.Validate(); e != nil {
		t.Fatal(e)
	}
	p := &fakePublisher{}
	p.online.Store(true)
	r := NewRegistry(c, p)
	value := func() any {
		caps := r.Query("1", "lamp")["capabilities"].([]map[string]any)
		return caps[0]["state"].(map[string]any)["value"]
	}
	if value() != false {
		t.Fatal("initial state not reported")
	}
	if e := r.Act(context.Background(), "1", "lamp", onOff, State{Instance: "on", Value: true}); e != nil {
		t.Fatal(e)
	}
	if value() != true {
		t.Fatal("query still reports the initial state after a successful command")
	}
	// Неудачная публикация состояние не меняет.
	p.err = errors.New("broker rejected")
	if e := r.Act(context.Background(), "1", "lamp", onOff, State{Instance: "on", Value: false}); e == nil {
		t.Fatal("failed publish reported as success")
	}
	if value() != true {
		t.Fatal("failed publish changed the reported state")
	}
}

// Н2. Фиктивный bcrypt-хеш для несуществующего логина имел cost 10, а реальные
// хеши (-hash-password, миграция) — cost 12: ответ для несуществующего имени
// примерно в 4 раза быстрее, что позволяет перебирать имена пользователей.
func TestDummyHashMatchesUserCost(t *testing.T) {
	c := testConfig(t)
	h, e := bcrypt.GenerateFromPassword([]byte("pw"), 12)
	if e != nil {
		t.Fatal(e)
	}
	c.Users[0].PasswordHash = string(h)
	st, _ := OpenStore(c.DataFile)
	s, e := NewServer(c, NewRegistry(c, &fakePublisher{}), st, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if e != nil {
		t.Fatal(e)
	}
	if cost, _ := bcrypt.Cost(s.dummyHash); cost != 12 {
		t.Fatalf("dummy hash cost %d differs from user hash cost 12", cost)
	}
}

// Н3. Собственный TLS читал сертификат один раз при запуске. После обновления
// Let's Encrypt процесс продолжал отдавать старый сертификат до перезапуска,
// а через 90 дней Яндекс переставал подключаться.
func TestCertificateReloadAfterRenewal(t *testing.T) {
	dir := t.TempDir()
	certFile, keyFile := filepath.Join(dir, "fullchain.pem"), filepath.Join(dir, "privkey.pem")
	writeTestCert(t, certFile, keyFile, "first")
	cr, e := NewCertReloader(certFile, keyFile, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if e != nil {
		t.Fatal(e)
	}
	cr.interval = 0
	name := func() string {
		c, e := cr.GetCertificate(&tls.ClientHelloInfo{})
		if e != nil {
			t.Fatal(e)
		}
		x, _ := x509.ParseCertificate(c.Certificate[0])
		return x.Subject.CommonName
	}
	if name() != "first" {
		t.Fatal("initial certificate not served")
	}
	time.Sleep(10 * time.Millisecond)
	writeTestCert(t, certFile, keyFile, "renewed")
	future := time.Now().Add(time.Second)
	os.Chtimes(certFile, future, future)
	os.Chtimes(keyFile, future, future)
	if name() != "renewed" {
		t.Fatal("renewed certificate not picked up without restart")
	}
	// Повреждённый файл не роняет сервер: продолжает работать последний валидный.
	os.WriteFile(certFile, []byte("broken"), 0600)
	later := future.Add(time.Second)
	os.Chtimes(certFile, later, later)
	if name() != "renewed" {
		t.Fatal("broken renewal replaced the working certificate")
	}
}

func writeTestCert(t *testing.T, certFile, keyFile, cn string) {
	t.Helper()
	key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	tpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: cn}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), DNSNames: []string{cn}}
	der, e := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if e != nil {
		t.Fatal(e)
	}
	kb, _ := x509.MarshalECPrivateKey(key)
	os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600)
	os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb}), 0600)
}
