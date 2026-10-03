package bridge

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

type notificationJob struct {
	Config NotificationConfig
	Change Change
	Time   float64
}
type Notifier struct {
	Config   []NotificationConfig
	Registry *Registry
	Store    *Store
	Log      *slog.Logger
	Client   *http.Client
	BaseURL  string
	jobs     chan notificationJob
	wg       sync.WaitGroup
}

func NewNotifier(c []NotificationConfig, r *Registry, s *Store, l *slog.Logger) *Notifier {
	return &Notifier{Config: c, Registry: r, Store: s, Log: l, Client: &http.Client{Timeout: 5 * time.Second, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}, BaseURL: "https://dialogs.yandex.net", jobs: make(chan notificationJob, 256)}
}
func localID(c NotificationConfig) string {
	if c.LocalUserID != "" {
		return c.LocalUserID
	}
	return c.UserID
}
func (n *Notifier) Enqueue(change Change) {
	for _, c := range n.Config {
		if !n.Registry.HasAccess(localID(c), change.DeviceID) || !n.Store.Linked(localID(c), c.ClientID) {
			continue
		}
		job := notificationJob{c, change, float64(time.Now().UnixNano()) / 1e9}
		select {
		case n.jobs <- job:
		default:
			n.Log.Warn("notification queue full; notification dropped", "device", change.DeviceID)
		}
	}
}
func (n *Notifier) Start(ctx context.Context) {
	for i := 0; i < 1; i++ {
		n.wg.Add(1)
		go func() {
			defer n.wg.Done()
			for {
				select {
				case <-ctx.Done():
					return
				case job := <-n.jobs:
					n.send(ctx, job)
				}
			}
		}()
	}
}
func (n *Notifier) Wait() { n.wg.Wait() }
func (n *Notifier) send(ctx context.Context, j notificationJob) {
	device := map[string]any{"id": j.Change.DeviceID}
	if len(j.Change.Capabilities) > 0 {
		device["capabilities"] = j.Change.Capabilities
	}
	if len(j.Change.Properties) > 0 {
		device["properties"] = j.Change.Properties
	}
	b, e := json.Marshal(map[string]any{"ts": j.Time, "payload": map[string]any{"user_id": j.Config.UserID, "devices": []any{device}}})
	if e != nil {
		n.Log.Error("notification encoding failed")
		return
	}
	endpoint := strings.TrimRight(n.BaseURL, "/") + "/api/v1/skills/" + url.PathEscape(j.Config.SkillID) + "/callback/state"
	for attempt := 0; attempt < 3; attempt++ {
		if !n.Store.Linked(localID(j.Config), j.Config.ClientID) || !n.Registry.HasAccess(localID(j.Config), j.Change.DeviceID) {
			return
		}
		req, e := http.NewRequestWithContext(ctx, "POST", endpoint, bytes.NewReader(b))
		if e != nil {
			n.Log.Error("notification request failed")
			return
		}
		req.Header.Set("Authorization", "OAuth "+j.Config.Token)
		req.Header.Set("Content-Type", "application/json")
		res, err := n.Client.Do(req)
		status := 0
		retry := true
		if err == nil {
			status = res.StatusCode
			body, readErr := io.ReadAll(io.LimitReader(res.Body, 64<<10))
			res.Body.Close()
			var reply struct {
				RequestID string `json:"request_id"`
				Status    string `json:"status"`
				ErrorCode string `json:"error_code"`
			}
			parsed := json.Unmarshal(body, &reply) == nil
			if parsed && reply.RequestID != "" {
				n.Log.Info("notification response", "request_id", reply.RequestID, "status", status, "result", reply.Status, "error_code", reply.ErrorCode)
			}
			if status >= 200 && status < 300 && readErr == nil && parsed && reply.Status == "ok" {
				return
			}
			retry = status == 429 || status >= 500 || status >= 200 && status < 300 && !parsed
		}
		if ctx.Err() != nil {
			return
		}
		n.Log.Warn("notification failed", "status", status, "attempt", attempt+1, "device", j.Change.DeviceID)
		if !retry || attempt == 2 {
			return
		}
		timer := time.NewTimer(time.Duration(attempt+1) * time.Second)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
	}
}

// sha256Base64 implements PKCE S256, unlike the hex storage hash.
func sha256Base64(s string) string { return pkceHash(s) }
