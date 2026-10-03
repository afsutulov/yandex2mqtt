package bridge

import (
	"context"
	"errors"
	"fmt"
	"math"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestProductionRefreshRetryIdempotent(t *testing.T) {
	s, _, _ := fixture(t)
	first := issue(t, s, "1", "yandex-client")
	next, err := s.Store.Refresh(first.RefreshToken, "yandex-client", s.Config.OAuth)
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			retry, err := s.Store.Refresh(first.RefreshToken, "yandex-client", s.Config.OAuth)
			if err != nil || retry.AccessToken != next.AccessToken || retry.RefreshToken != next.RefreshToken {
				t.Error("duplicate refresh must return the same live pair", err)
			}
		}()
	}
	wg.Wait()
	if _, ok := s.Store.Find(next.AccessToken); !ok {
		t.Fatal("delayed first response contains an invalid access token")
	}
	reopened, err := OpenStore(s.Config.DataFile)
	if err != nil {
		t.Fatal(err)
	}
	retry, err := reopened.Refresh(first.RefreshToken, "yandex-client", s.Config.OAuth)
	if err != nil || retry.AccessToken != next.AccessToken || retry.RefreshToken != next.RefreshToken {
		t.Fatal("retry not stable across restart", err)
	}
	data, err := os.ReadFile(s.Config.DataFile)
	if err != nil {
		t.Fatal(err)
	}
	for _, token := range []string{first.AccessToken, first.RefreshToken, next.AccessToken, next.RefreshToken} {
		if strings.Contains(string(data), token) {
			t.Fatal("raw token stored on disk")
		}
	}
	if _, err := reopened.Refresh(next.RefreshToken, "yandex-client", s.Config.OAuth); err != nil {
		t.Fatal(err)
	}
	if _, err := reopened.Refresh(first.RefreshToken, "yandex-client", s.Config.OAuth); err == nil {
		t.Fatal("retry from an older generation accepted")
	}
}

func TestProductionRateTableDoesNotGloballyBlock(t *testing.T) {
	s, _, _ := fixture(t)
	for i := range 10050 {
		r := httptest.NewRequest("POST", "/login", nil)
		r.RemoteAddr = fmt.Sprintf("10.%d.%d.%d:1234", i>>16, (i>>8)&255, i&255)
		s.limited(r, "login")
	}
	r := httptest.NewRequest("POST", "/login", nil)
	r.RemoteAddr = "198.51.100.7:1234"
	for range 30 {
		if s.limited(r, "login") {
			t.Fatal("new legitimate peer denied because global table is full")
		}
	}
	if !s.limited(r, "login") {
		t.Fatal("active peer limit lost under table pressure")
	}
	if len(s.rates) > 10000 {
		t.Fatal("unbounded limiter")
	}
	r.RemoteAddr = "[2001:db8:1234:5678::1]:1234"
	if s.limited(r, "login") {
		t.Fatal("unrelated IPv6 subnet denied")
	}
}

func TestProductionActionReturnsBeforeYandexDeadline(t *testing.T) {
	s, r, p := fixture(t)
	r.devices["lamp"].config.MQTT[0].ConfirmTimeoutMS = 2000
	tok := issue(t, s, "1", "yandex-client")
	start := time.Now()
	w := request(t, s, "POST", "/v1.0/user/devices/action", tok.AccessToken, `{"payload":{"devices":[{"id":"lamp","capabilities":[{"type":"devices.capabilities.on_off","state":{"instance":"on","value":true}},{"type":"devices.capabilities.on_off","state":{"instance":"on","value":false}}]}]}}`)
	if elapsed := time.Since(start); elapsed >= 3*time.Second {
		t.Fatalf("response missed Yandex's 3s end-to-end timeout: %s", elapsed)
	}
	if w.Code != 200 || !strings.Contains(w.Body.String(), "ERROR") || p.count() != 2 {
		t.Fatal(w.Code, w.Body.String(), p.count())
	}
}

func commandOnlyRange(t *testing.T, initial *State) (*Registry, *fakePublisher) {
	t.Helper()
	c := testConfig(t)
	c.Devices[0].Capabilities = []Feature{{Type: "devices.capabilities.range", State: initial, Parameters: map[string]any{"instance": "volume", "range": map[string]any{"min": float64(0), "max": float64(100)}}}}
	c.Devices[0].MQTT = []Binding{{Instance: "volume", Set: "volume/set"}}
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	return regressionRegistry(t, c)
}

func TestProductionCommandOnlyInitialStateDoesNotFreezeBase(t *testing.T) {
	r, p := commandOnlyRange(t, &State{Instance: "volume", Value: float64(30)})
	for _, command := range []State{{Instance: "volume", Value: float64(60)}, {Instance: "volume", Value: float64(10), Relative: true}, {Instance: "volume", Value: float64(10), Relative: true}} {
		if err := r.Act(context.Background(), "1", "lamp", "devices.capabilities.range", command); err != nil {
			t.Fatal(err)
		}
	}
	if got := p.messages[len(p.messages)-1]; got != "volume/set=80" {
		t.Fatal("initial configuration overrides last successful command:", got)
	}
}

func TestProductionFailedPublishDoesNotAdvanceRelativeBase(t *testing.T) {
	r, p := commandOnlyRange(t, nil)
	abs := State{Instance: "volume", Value: float64(30)}
	if err := r.Act(context.Background(), "1", "lamp", "devices.capabilities.range", abs); err != nil {
		t.Fatal(err)
	}
	p.err = errors.New("publish failed")
	abs.Value = float64(60)
	if err := r.Act(context.Background(), "1", "lamp", "devices.capabilities.range", abs); err == nil {
		t.Fatal("failed publication accepted")
	}
	p.err = nil
	if err := r.Act(context.Background(), "1", "lamp", "devices.capabilities.range", State{Instance: "volume", Value: float64(10), Relative: true}); err != nil {
		t.Fatal(err)
	}
	if got := p.messages[len(p.messages)-1]; got != "volume/set=40" {
		t.Fatal("failed command became relative base:", got)
	}
}

func TestProductionRefreshGraceCannotExtendExpiredCredential(t *testing.T) {
	s, _, _ := fixture(t)
	first := issue(t, s, "1", "yandex-client")
	expires := time.Now().Unix() + 1
	s.Store.tokens[0].RefreshExpires = expires
	if _, err := s.Store.Refresh(first.RefreshToken, "yandex-client", s.Config.OAuth); err != nil {
		t.Fatal(err)
	}
	if s.Store.tokens[0].PrevRefreshExpires > expires {
		t.Fatal("grace window extends the old refresh token's original lifetime")
	}
}

func TestProductionRefreshRetryDoesNotNeedDiskWrite(t *testing.T) {
	s, _, _ := fixture(t)
	first := issue(t, s, "1", "yandex-client")
	next, err := s.Store.Refresh(first.RefreshToken, "yandex-client", s.Config.OAuth)
	if err != nil {
		t.Fatal(err)
	}
	block := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(block, []byte("blocked"), 0600); err != nil {
		t.Fatal(err)
	}
	s.Store.path = filepath.Join(block, "tokens.json")
	retry, err := s.Store.Refresh(first.RefreshToken, "yandex-client", s.Config.OAuth)
	if err != nil || retry.AccessToken != next.AccessToken || retry.RefreshToken != next.RefreshToken {
		t.Fatal("persisted refresh retry unexpectedly writes new tokens", err)
	}
}

func TestProductionRefreshLegacyGraceUpgrade(t *testing.T) {
	s, _, _ := fixture(t)
	old := issue(t, s, "1", "yandex-client")
	live := issue(t, s, "1", "yandex-client")
	// Model the actual 1.2.1 disk format: independently random tokens and
	// only the previous hash and deadline. There is no derivation nonce.
	legacy := s.Store.tokens[1]
	legacy.PrevRefreshHash = hashToken(old.RefreshToken)
	legacy.PrevRefreshExpires = time.Now().Unix() + refreshGrace
	if err := s.Store.save([]TokenRecord{legacy}); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenStore(s.Config.DataFile)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := reopened.Find(live.AccessToken); !ok {
		t.Fatal("current legacy pair lost on upgrade")
	}
	upgraded, err := reopened.Refresh(old.RefreshToken, "yandex-client", s.Config.OAuth)
	if err != nil {
		t.Fatal(err)
	}
	reopened, err = OpenStore(s.Config.DataFile)
	if err != nil {
		t.Fatal(err)
	}
	retry, err := reopened.Refresh(old.RefreshToken, "yandex-client", s.Config.OAuth)
	if err != nil || retry.AccessToken != upgraded.AccessToken || retry.RefreshToken != upgraded.RefreshToken {
		t.Fatal("legacy grace record did not upgrade to stable retries", err)
	}
	if reopened.tokens[0].PrevRefreshExpires != legacy.PrevRefreshExpires {
		t.Fatal("legacy upgrade extended retry window")
	}
	if err := reopened.Revoke("1", "yandex-client"); err != nil {
		t.Fatal(err)
	}
	if _, err := reopened.Refresh(old.RefreshToken, "yandex-client", s.Config.OAuth); err == nil {
		t.Fatal("revoked legacy retry accepted")
	}
}

func TestProductionIncrementalRangeNeedsNoAbsoluteBase(t *testing.T) {
	for _, bounds := range []bool{true, false} {
		t.Run(fmt.Sprintf("bounds=%t", bounds), func(t *testing.T) {
			c := testConfig(t)
			params := map[string]any{"instance": "volume", "random_access": false}
			if bounds {
				params["range"] = map[string]any{"min": float64(0), "max": float64(100)}
			}
			c.Devices[0].Capabilities = []Feature{{Type: "devices.capabilities.range", Retrievable: true, Reportable: true, Parameters: params}}
			c.Devices[0].MQTT = []Binding{{Instance: "volume", Set: "ir/volume/step"}}
			c.Devices[0].ValueMapping = nil
			if err := c.Validate(); err != nil {
				t.Fatal(err)
			}
			r, p := regressionRegistry(t, c)
			for _, delta := range []float64{10, -10} {
				if err := r.Act(context.Background(), "1", "lamp", "devices.capabilities.range", State{Instance: "volume", Value: delta, Relative: true}); err != nil {
					t.Fatal("increment command requires an absolute base", err)
				}
			}
			if p.messages[0] != "ir/volume/step=10" || p.messages[1] != "ir/volume/step=-10" {
				t.Fatal("MQTT did not receive signed deltas", p.messages)
			}
			for _, bad := range []State{{Instance: "volume", Value: float64(50)}, {Instance: "volume", Value: math.NaN(), Relative: true}, {Instance: "volume", Value: math.Inf(1), Relative: true}} {
				if err := r.Act(context.Background(), "1", "lamp", "devices.capabilities.range", bad); err == nil {
					t.Fatal("invalid incremental action accepted")
				}
			}
			if p.count() != 2 || len(r.devices["lamp"].commanded) != 0 {
				t.Fatal("increment invented an absolute state")
			}
			cap := r.Discovery("1")[0]["capabilities"].([]map[string]any)[0]
			if cap["retrievable"] != false || cap["reportable"] != false {
				t.Fatal("increment-only device claims feedback")
			}
			r.devices["lamp"].config.ValueMapping = []ValueMapping{{Type: "range", Instance: "volume", Mapping: [][]any{{float64(10), float64(-10)}, {"UP", "DOWN"}}}}
			for _, delta := range []float64{10, -10} {
				if err := r.Act(context.Background(), "1", "lamp", "devices.capabilities.range", State{Instance: "volume", Value: delta, Relative: true}); err != nil {
					t.Fatal(err)
				}
			}
			if p.messages[2] != "ir/volume/step=UP" || p.messages[3] != "ir/volume/step=DOWN" {
				t.Fatal("increment mapping broken", p.messages)
			}
			p.err = errors.New("publish rejected")
			if err := r.Act(context.Background(), "1", "lamp", "devices.capabilities.range", State{Instance: "volume", Value: float64(10), Relative: true}); err == nil {
				t.Fatal("failed increment publication accepted")
			}
			c.Devices[0].MQTT[0].State = "ir/volume/state"
			c.Devices[0].MQTT[0].ConfirmTimeoutMS = 100
			if err := c.Validate(); err == nil {
				t.Fatal("increment-only function accepts absolute target confirmation")
			}
		})
	}
}
