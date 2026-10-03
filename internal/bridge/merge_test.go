package bridge

import (
	"context"
	"math"
	"strings"
	"testing"
	"time"
)

func TestProviderPathsPreservePOSTAndAuthorization(t *testing.T) {
	s, _, p := fixture(t)
	token := issue(t, s, "1", "yandex-client")
	for _, path := range []string{"/provider//v1.0/user/devices/action/", "/provider///v1.0//user/devices/action", "//provider/v1.0/user/devices/action/", "/v1.0//user/devices/action/"} {
		w := request(t, s, "POST", path, token.AccessToken, `{"payload":{"devices":[{"id":"lamp","capabilities":[{"type":"devices.capabilities.on_off","state":{"instance":"on","value":true}}]}]}}`)
		if w.Code != 200 || w.Header().Get("Location") != "" || !strings.Contains(w.Body.String(), "DONE") {
			t.Fatal(path, w.Code, w.Body.String())
		}
		if w = request(t, s, "POST", path, "", `{"payload":{"devices":[]}}`); w.Code != 401 {
			t.Fatal("normalization bypassed auth", path, w.Code)
		}
	}
	if p.count() != 4 {
		t.Fatal(p.count())
	}
	for _, path := range []string{"/provider", "/provider/v1.0", "/v1.0"} {
		if w := request(t, s, "GET", path, "", ""); w.Code != 200 {
			t.Fatal(path, w.Code)
		}
	}
	for _, path := range []string{"/v1.0/", "/provider//v1.0/"} {
		if w := request(t, s, "HEAD", path, "", ""); w.Code != 200 || w.Body.Len() != 0 {
			t.Fatal(path, w.Code)
		}
	}
	if w := request(t, s, "GET", "/provider-evil//v1.0", "", ""); w.Code == 200 {
		t.Fatal("unrelated path treated as provider")
	}
}
func TestRelativeRangeSaturationAndPrecision(t *testing.T) {
	c := testConfig(t)
	kind := "devices.capabilities.range"
	f := Feature{Type: kind, Retrievable: true, Parameters: map[string]any{"instance": "brightness", "range": map[string]any{"min": float64(1), "max": float64(100), "precision": float64(2)}}}
	c.Devices[0].Capabilities = []Feature{f}
	c.Devices[0].ValueMapping = nil
	c.Devices[0].MQTT = []Binding{{Instance: "brightness", State: "brightness", Set: "brightness/set"}}
	if e := c.Validate(); e != nil {
		t.Fatal(e)
	}
	r, p := regressionRegistry(t, c)
	for _, x := range []struct {
		state string
		delta float64
		want  string
	}{{"97.5", 10, "99"}, {"2", -20, "1"}, {"22.3", 1, "23"}} {
		if e := r.Update("brightness", []byte(x.state)); len(e) > 0 {
			t.Fatal(e)
		}
		if e := r.Act(context.Background(), "1", "lamp", kind, State{Instance: "brightness", Value: x.delta, Relative: true}); e != nil {
			t.Fatal(e)
		}
		if p.messages[len(p.messages)-1] != "brightness/set="+x.want {
			t.Fatal(p.messages)
		}
	}
	for _, delta := range []float64{math.NaN(), math.Inf(1)} {
		if e := r.Act(context.Background(), "1", "lamp", kind, State{Instance: "brightness", Value: delta, Relative: true}); e == nil {
			t.Fatal("nonfinite delta accepted")
		}
	}
	// Absolute commands stay strict.
	if e := r.Act(context.Background(), "1", "lamp", kind, State{Instance: "brightness", Value: float64(100)}); e == nil {
		t.Fatal("off-grid absolute command accepted")
	}
}
func TestActionPanicRecoveryAndNextEntry(t *testing.T) {
	s, _, p := fixture(t)
	first := true
	p.hook = func(string, []byte) {
		if first {
			first = false
			panic("simulated publisher fault")
		}
	}
	token := issue(t, s, "1", "yandex-client")
	w := request(t, s, "POST", "/v1.0/user/devices/action", token.AccessToken, `{"payload":{"devices":[{"id":"lamp","capabilities":[{"type":"devices.capabilities.on_off","state":{"instance":"on","value":true}}]},{"id":"lamp","capabilities":[{"type":"devices.capabilities.on_off","state":{"instance":"on","value":false}}]}]}}`)
	if w.Code != 200 || !strings.Contains(w.Body.String(), "INTERNAL_ERROR") || !strings.Contains(w.Body.String(), "DONE") || p.count() != 2 {
		t.Fatal(w.Code, w.Body.String())
	}
}
func TestColorSceneIDsAndTemperatureTelemetry(t *testing.T) {
	for _, key := range []string{"id", "value"} {
		t.Run(key, func(t *testing.T) {
			c := testConfig(t)
			kind := "devices.capabilities.color_setting"
			c.Devices[0].Capabilities = []Feature{{Type: kind, Retrievable: true, Parameters: map[string]any{"temperature_k": map[string]any{}, "color_scene": map[string]any{"scenes": []any{map[string]any{key: "reading"}}}}}}
			c.Devices[0].ValueMapping = nil
			c.Devices[0].MQTT = []Binding{{Instance: "temperature_k", Set: "temperature/set", State: "temperature"}, {Instance: "scene", Set: "scene/set", State: "scene"}}
			if e := c.Validate(); e != nil {
				t.Fatal(e)
			}
			r, p := regressionRegistry(t, c)
			if es := r.Update("temperature", []byte("1500")); len(es) > 0 {
				t.Fatal(es)
			}
			if e := r.Act(context.Background(), "1", "lamp", kind, State{Instance: "temperature_k", Value: float64(4500)}); e != nil {
				t.Fatal(e)
			}
			if e := r.Act(context.Background(), "1", "lamp", kind, State{Instance: "temperature_k", Value: float64(1500)}); e == nil {
				t.Fatal("out-of-range color command accepted")
			}
			if e := r.Act(context.Background(), "1", "lamp", kind, State{Instance: "scene", Value: "reading"}); e != nil {
				t.Fatal(e)
			}
			if len(p.messages) != 2 {
				t.Fatal(p.messages)
			}
			params := r.Discovery("1")[0]["capabilities"].([]map[string]any)[0]["parameters"].(map[string]any)
			scene := params["color_scene"].(map[string]any)["scenes"].([]any)[0].(map[string]any)
			if scene["id"] != "reading" || scene["value"] != nil {
				t.Fatal(scene)
			}
			if es := r.Update("temperature", []byte("-1")); len(es) == 0 {
				t.Fatal("negative Kelvin accepted")
			}
		})
	}
}
func TestFailedSubscriptionRejectsRelativeAndConfirmation(t *testing.T) {
	c := testConfig(t)
	c.Devices[0].MQTT[0].ConfirmTimeoutMS = 100
	r, p := regressionRegistry(t, c)
	r.Update("home/Lamp/state", []byte("1"))
	r.SetTopicAvailable("home/Lamp/state", false)
	if e := r.Act(context.Background(), "1", "lamp", onOff, State{Instance: "on", Value: true}); e == nil || p.count() != 0 {
		t.Fatal("command awaiting unreadable state was published")
	}
	r.SetTopicAvailable("home/Lamp/state", true)
	p.hook = func(string, []byte) { r.Update("home/Lamp/state", []byte("1")) }
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if e := r.Act(ctx, "1", "lamp", onOff, State{Instance: "on", Value: true}); e != nil {
		t.Fatal(e)
	}
}
