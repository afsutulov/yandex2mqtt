package bridge

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"sync/atomic"
	"time"

	mqtt "github.com/eclipse/paho.mqtt.golang"
)

type MQTT struct {
	client  mqtt.Client
	options *mqtt.ClientOptions
	config  MQTTConfig
	log     *slog.Logger
	ready   atomic.Bool
}

func NewMQTT(c MQTTConfig, l *slog.Logger) (*MQTT, error) {
	m := &MQTT{config: c, log: l}
	broker := c.URL
	if strings.HasPrefix(broker, "mqtt://") {
		broker = "tcp://" + strings.TrimPrefix(broker, "mqtt://")
	}
	if strings.HasPrefix(broker, "mqtts://") {
		broker = "ssl://" + strings.TrimPrefix(broker, "mqtts://")
	}
	opts := mqtt.NewClientOptions().AddBroker(broker).SetClientID(c.ClientID).SetUsername(c.User).SetPassword(c.Password).
		SetProtocolVersion(4).SetCleanSession(true).SetAutoReconnect(true).SetConnectRetry(true).
		SetConnectRetryInterval(2 * time.Second).SetMaxReconnectInterval(30 * time.Second).
		SetConnectTimeout(5 * time.Second).SetWriteTimeout(time.Duration(c.TimeoutMS) * time.Millisecond).
		SetKeepAlive(30 * time.Second).SetPingTimeout(5 * time.Second).SetOrderMatters(true)
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
	if c.CAFile != "" {
		pem, e := os.ReadFile(c.CAFile)
		if e != nil {
			return nil, e
		}
		pool, e := x509.SystemCertPool()
		if e != nil {
			pool = x509.NewCertPool()
		}
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("MQTT CA file contains no certificates")
		}
		tlsConfig.RootCAs = pool
	}
	if c.CertFile != "" {
		cert, e := tls.LoadX509KeyPair(c.CertFile, c.KeyFile)
		if e != nil {
			return nil, e
		}
		tlsConfig.Certificates = []tls.Certificate{cert}
	}
	opts.SetTLSConfig(tlsConfig)
	opts.SetConnectionLostHandler(func(_ mqtt.Client, _ error) { m.ready.Store(false); l.Warn("MQTT disconnected; reconnecting") })
	m.options = opts
	return m, nil
}
func (m *MQTT) Start(ctx context.Context, r *Registry) {
	o := m.options
	o.SetConnectionLostHandler(func(_ mqtt.Client, _ error) { m.ready.Store(false); m.log.Warn("MQTT disconnected; reconnecting") })
	o.SetOnConnectHandler(func(c mqtt.Client) {
		m.ready.Store(false)
		r.Invalidate()
		topics := r.Topics()
		if len(topics) == 0 {
			m.ready.Store(true)
			m.log.Info("MQTT connected")
			return
		}
		filters := map[string]byte{}
		for _, t := range topics {
			filters[t] = m.config.QoS
		}
		token := c.SubscribeMultiple(filters, func(_ mqtt.Client, msg mqtt.Message) {
			if len(msg.Payload()) > 1<<20 {
				m.log.Warn("MQTT payload too large")
				return
			}
			for _, e := range r.Update(msg.Topic(), msg.Payload()) {
				m.log.Warn("invalid MQTT state", "error", e.Error())
			}
		})
		if !token.WaitTimeout(5*time.Second) || token.Error() != nil {
			m.log.Error("MQTT subscribe failed")
			m.ready.Store(false)
			go func() {
				c.Disconnect(100)
				select {
				case <-ctx.Done():
					return
				case <-time.After(2 * time.Second):
					c.Connect()
				}
			}()
			return
		}
		// SubscribeMultiple can succeed as an operation but return rejected individual filters.
		if st, ok := token.(*mqtt.SubscribeToken); ok {
			for _, qos := range st.Result() {
				if qos == 0x80 {
					m.log.Error("MQTT subscription rejected")
					m.ready.Store(false)
					return
				}
			}
		}
		m.ready.Store(true)
		m.log.Info("MQTT connected and subscribed", "topics", len(topics))
	})
	m.client = mqtt.NewClient(o)
	token := m.client.Connect()
	go func() {
		select {
		case <-ctx.Done():
			return
		case <-token.Done():
			if token.Error() != nil {
				m.log.Error("MQTT connection failed")
			}
		}
	}()
}
func (m *MQTT) Connected() bool {
	return m.ready.Load() && m.client != nil && m.client.IsConnectionOpen()
}
func (m *MQTT) Publish(ctx context.Context, topic string, payload []byte) error {
	if e := ctx.Err(); e != nil {
		return e
	}
	if !m.Connected() {
		return fmt.Errorf("MQTT unavailable")
	}
	token := m.client.Publish(topic, m.config.QoS, false, payload)
	timer := time.NewTimer(time.Duration(m.config.TimeoutMS) * time.Millisecond)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return fmt.Errorf("publish timeout")
	case <-token.Done():
		return token.Error()
	}
}
func (m *MQTT) Close() { m.ready.Store(false); m.client.Disconnect(250) }
