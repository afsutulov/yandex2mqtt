package bridge

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	mqtt "github.com/eclipse/paho.mqtt.golang"
)

type MQTT struct {
	client           mqtt.Client
	options          *mqtt.ClientOptions
	config           MQTTConfig
	log              *slog.Logger
	ready            atomic.Bool
	mu               sync.Mutex
	connectionCancel context.CancelFunc
	status           SubscriptionStatus
	stopping         bool
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

type SubscriptionStatus struct {
	Total    int  `json:"total"`
	Active   int  `json:"active"`
	Pending  int  `json:"pending"`
	Degraded bool `json:"degraded"`
}

func (m *MQTT) SubscriptionStatus() SubscriptionStatus {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.status
}
func (m *MQTT) Start(ctx context.Context, r *Registry) {
	o := m.options
	o.SetConnectionLostHandler(func(_ mqtt.Client, _ error) {
		m.mu.Lock()
		if m.connectionCancel != nil {
			m.connectionCancel()
		}
		m.ready.Store(false)
		m.mu.Unlock()
		m.log.Warn("MQTT disconnected; reconnecting")
	})
	o.SetOnConnectHandler(func(c mqtt.Client) {
		m.mu.Lock()
		if m.stopping || ctx.Err() != nil {
			m.mu.Unlock()
			return
		}
		if m.connectionCancel != nil {
			m.connectionCancel()
		}
		connectionCtx, cancel := context.WithCancel(ctx)
		m.connectionCancel = cancel
		m.ready.Store(false)
		m.mu.Unlock()
		if m.config.ResetStateOnReconnect {
			r.Invalidate()
		}
		topics := r.Topics()
		pending := map[string]byte{}
		for _, t := range topics {
			pending[t] = m.config.QoS
		}
		m.mu.Lock()
		m.status = SubscriptionStatus{Total: len(topics), Pending: len(topics), Degraded: len(topics) > 0}
		m.mu.Unlock()
		// Retry only failed filters; successful subscriptions remain usable.
		go func() {
			handler := func(_ mqtt.Client, msg mqtt.Message) {
				if len(msg.Payload()) > 1<<20 {
					m.log.Warn("MQTT payload too large")
					return
				}
				for _, e := range r.Update(msg.Topic(), msg.Payload()) {
					m.log.Warn("invalid MQTT state", "error", e.Error())
				}
			}
			for {
				if connectionCtx.Err() != nil || !c.IsConnectionOpen() {
					return
				}
				if len(pending) > 0 {
					filters := map[string]byte{}
					for t, q := range pending {
						filters[t] = q
					}
					token := c.SubscribeMultiple(filters, handler)
					timer := time.NewTimer(5 * time.Second)
					select {
					case <-connectionCtx.Done():
						timer.Stop()
						return
					case <-timer.C:
					case <-token.Done():
						timer.Stop()
					}
					if connectionCtx.Err() != nil {
						return
					}
					success := false
					select {
					case <-token.Done():
						success = token.Error() == nil
					default:
					}
					if success {
						if st, ok := token.(*mqtt.SubscribeToken); ok {
							for t := range filters {
								q, found := st.Result()[t]
								available := found && q != 0x80
								r.SetTopicAvailable(t, available)
								if available {
									delete(pending, t)
								} else {
									m.log.Warn("MQTT subscription rejected; will retry", "topic", t)
								}
							}
						}
					}
					if !success {
						for t := range filters {
							r.SetTopicAvailable(t, false)
						}
						m.log.Warn("MQTT subscription attempt failed; will retry")
					}
				}
				m.mu.Lock()
				if connectionCtx.Err() != nil || m.stopping {
					m.mu.Unlock()
					return
				}
				m.status = SubscriptionStatus{Total: len(topics), Active: len(topics) - len(pending), Pending: len(pending), Degraded: len(pending) > 0}
				m.ready.Store(c.IsConnectionOpen())
				m.mu.Unlock()
				if len(pending) == 0 {
					m.log.Info("MQTT connected and subscribed", "topics", len(topics))
					return
				}
				timer := time.NewTimer(2 * time.Second)
				select {
				case <-connectionCtx.Done():
					timer.Stop()
					return
				case <-timer.C:
				}
			}
		}()
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
func (m *MQTT) Close() {
	m.mu.Lock()
	m.stopping = true
	m.ready.Store(false)
	if m.connectionCancel != nil {
		m.connectionCancel()
	}
	m.mu.Unlock()
	if m.client != nil {
		m.client.Disconnect(250)
	}
}
