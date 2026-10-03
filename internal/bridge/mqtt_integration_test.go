package bridge

import (
	"context"
	"io"
	"log/slog"
	"testing"
	"time"

	paho "github.com/eclipse/paho.mqtt.golang"
	broker "github.com/mochi-mqtt/server/v2"
	"github.com/mochi-mqtt/server/v2/hooks/auth"
	"github.com/mochi-mqtt/server/v2/listeners"
)

func waitUntil(t *testing.T, timeout time.Duration, fn func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if fn() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("condition was not met before deadline")
}
func mqttWait(t *testing.T, token paho.Token) {
	t.Helper()
	if !token.WaitTimeout(3*time.Second) || token.Error() != nil {
		t.Fatal("MQTT operation failed", token.Error())
	}
}
func TestMQTTIntegrationRetainedPublishAndReconnect(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	b := broker.New(&broker.Options{Logger: log, InlineClient: true})
	if e := b.AddHook(&auth.AllowHook{}, nil); e != nil {
		t.Fatal(e)
	}
	listener := listeners.NewTCP(listeners.Config{ID: "tcp", Address: "127.0.0.1:0"})
	if e := b.AddListener(listener); e != nil {
		t.Fatal(e)
	}
	if e := b.Serve(); e != nil {
		t.Fatal(e)
	}
	addr := listener.Address()
	closed := false
	defer func() {
		if !closed {
			b.Close()
		}
	}()
	if e := b.Publish("home/Lamp/state", []byte("0"), true, 1); e != nil {
		t.Fatal(e)
	}
	c := testConfig(t)
	c.MQTT.URL = "tcp://" + addr
	c.MQTT.QoS = 1
	c.MQTT.ClientID = "bridge-under-test"
	c.Devices[0].MQTT[0].ConfirmTimeoutMS = 1000
	m, e := NewMQTT(c.MQTT, log)
	if e != nil {
		t.Fatal(e)
	}
	r := NewRegistry(c, m)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	m.Start(ctx, r)
	defer m.Close()
	waitUntil(t, 4*time.Second, func() bool { return m.Connected() && r.Query("1", "lamp")["error_code"] == nil })
	opts := paho.NewClientOptions().AddBroker("tcp://" + addr).SetClientID("simulated-lamp").SetOrderMatters(false)
	lamp := paho.NewClient(opts)
	mqttWait(t, lamp.Connect())
	defer lamp.Disconnect(100)
	received := make(chan string, 4)
	mqttWait(t, lamp.Subscribe("home/lamp/set", 1, func(cl paho.Client, msg paho.Message) {
		received <- string(msg.Payload())
		cl.Publish("home/Lamp/state", 1, true, msg.Payload())
	}))
	if e = r.Act(context.Background(), "1", "lamp", onOff, State{Instance: "on", Value: true}); e != nil {
		t.Fatal(e)
	}
	select {
	case v := <-received:
		if v != "1" {
			t.Fatal(v)
		}
	case <-time.After(time.Second):
		t.Fatal("command not published")
	}
	state := r.Query("1", "lamp")["capabilities"].([]map[string]any)[0]["state"].(map[string]any)["value"]
	if state != true {
		t.Fatal("state not updated by actual MQTT echo")
	}
	lamp.Disconnect(100)
	if e = b.Close(); e != nil {
		t.Fatal(e)
	}
	closed = true
	waitUntil(t, 3*time.Second, func() bool { return !m.Connected() })
	if e = r.Act(context.Background(), "1", "lamp", onOff, State{Instance: "on", Value: false}); e == nil {
		t.Fatal("command succeeded with offline broker")
	}
	// Restart the independent broker at exactly the same address.
	second := broker.New(&broker.Options{Logger: log, InlineClient: true})
	if e = second.AddHook(&auth.AllowHook{}, nil); e != nil {
		t.Fatal(e)
	}
	if e = second.AddListener(listeners.NewTCP(listeners.Config{ID: "tcp", Address: addr})); e != nil {
		t.Fatal(e)
	}
	if e = second.Serve(); e != nil {
		t.Fatal(e)
	}
	defer second.Close()
	if e = second.Publish("home/Lamp/state", []byte("0"), true, 1); e != nil {
		t.Fatal(e)
	}
	waitUntil(t, 8*time.Second, func() bool {
		if !m.Connected() {
			return false
		}
		q := r.Query("1", "lamp")
		if q["error_code"] != nil {
			return false
		}
		caps := q["capabilities"].([]map[string]any)
		return caps[0]["state"].(map[string]any)["value"] == false
	})
}
