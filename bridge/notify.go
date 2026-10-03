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
	mu       sync.Mutex
	paused   map[notificationKey]notificationPause
	now      func() time.Time
}

type notificationKey struct{ skill, user, client string }
type notificationPause struct {
	until      time.Time
	suppressed uint64
}

const notificationCooldown = 5 * time.Minute

func notificationID(c NotificationConfig) notificationKey {
	return notificationKey{c.SkillID, c.UserID, c.ClientID}
}

func NewNotifier(c []NotificationConfig, r *Registry, s *Store, l *slog.Logger) *Notifier {
	return &Notifier{Config: c, Registry: r, Store: s, Log: l, Client: &http.Client{Timeout: 5 * time.Second, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}, BaseURL: "https://dialogs.yandex.net", jobs: make(chan notificationJob, 256), paused: make(map[notificationKey]notificationPause), now: time.Now}
}
func localID(c NotificationConfig) string {
	if c.LocalUserID != "" {
		return c.LocalUserID
	}
	return c.UserID
}
func (n *Notifier) Enqueue(change Change) {
	for _, c := range n.Config {
		if !c.enabled() || !n.Registry.HasAccess(localID(c), change.DeviceID) || !n.Store.Linked(localID(c), c.ClientID) || n.isPaused(c) {
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

// A rejected skill or credential cannot be fixed by sending every MQTT update
// again. Pause only this recipient; queries and other skills keep working.
func (n *Notifier) isPaused(c NotificationConfig) bool {
	n.mu.Lock()
	defer n.mu.Unlock()
	key := notificationID(c)
	p, ok := n.paused[key]
	if !ok || !n.now().Before(p.until) {
		return false
	}
	p.suppressed++
	n.paused[key] = p
	return true
}

func (n *Notifier) pause(c NotificationConfig) uint64 {
	n.mu.Lock()
	defer n.mu.Unlock()
	key := notificationID(c)
	count := n.paused[key].suppressed
	n.paused[key] = notificationPause{until: n.now().Add(notificationCooldown)}
	return count
}

func (n *Notifier) recovered(c NotificationConfig) {
	n.mu.Lock()
	key := notificationID(c)
	p, ok := n.paused[key]
	delete(n.paused, key)
	n.mu.Unlock()
	if ok {
		n.Log.Info("notifications resumed", "skill_id", c.SkillID, "user_id", c.UserID, "suppressed", p.suppressed)
	}
}

func notificationReason(status int, code string) (string, string) {
	switch status {
	case http.StatusUnauthorized:
		return "invalid_oauth_token", "use a valid Dialogs OAuth token belonging to the skill owner"
	case http.StatusForbidden:
		return "skill_access_denied", "check that the Dialogs OAuth token belongs to the account that created the skill"
	case http.StatusNotFound:
		return "skill_not_found_or_unpublished", "publish the skill (private publication is sufficient) and check notification.skill_id against its published ID"
	case http.StatusBadRequest:
		if code == "UNKNOWN_USER" {
			return "unknown_user", "link the account to the published skill and set notification.user_id to the provider user ID from discovery"
		}
		return "invalid_payload", "check reportable device features and their state values"
	case http.StatusTooManyRequests:
		return "rate_limited", "reduce the frequency of state updates"
	case 0:
		return "network_error", "check network access to dialogs.yandex.net"
	default:
		if status >= 500 {
			return "upstream_error", "the notification service returned a temporary error"
		}
		return "unexpected_response", "the notification service did not return the expected success response"
	}
}

// Never log upstream bodies/error_message: they may echo authorization data.
func notificationErrorCode(s string) string {
	switch s {
	case "", "BAD_REQUEST", "UNKNOWN_USER", "UNAUTHORIZED", "FORBIDDEN", "NOT_FOUND", "SKILL_NOT_FOUND":
		return s
	default:
		return "UNRECOGNIZED_ERROR"
	}
}

func notificationRequestID(s, token string) string {
	if len(s) > 128 || token != "" && strings.Contains(s, token) {
		return ""
	}
	for _, ch := range s {
		if !(ch >= 'a' && ch <= 'z' || ch >= 'A' && ch <= 'Z' || ch >= '0' && ch <= '9' || strings.ContainsRune("-_.:", ch)) {
			return ""
		}
	}
	return s
}

func (n *Notifier) send(ctx context.Context, j notificationJob) {
	if !j.Config.enabled() || n.isPaused(j.Config) {
		return
	}
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
		requestID, errorCode := "", ""
		if err == nil {
			status = res.StatusCode
			body, readErr := io.ReadAll(io.LimitReader(res.Body, (64<<10)+1))
			res.Body.Close()
			var reply struct {
				RequestID string `json:"request_id"`
				Status    string `json:"status"`
				ErrorCode string `json:"error_code"`
			}
			parsed := readErr == nil && len(body) <= 64<<10 && json.Unmarshal(body, &reply) == nil
			if parsed {
				requestID = notificationRequestID(reply.RequestID, j.Config.Token)
				errorCode = notificationErrorCode(reply.ErrorCode)
			}
			if requestID == "" {
				requestID = notificationRequestID(res.Header.Get("X-Request-Id"), j.Config.Token)
			}
			if status >= 200 && status < 300 && parsed && reply.Status == "ok" {
				n.Log.Debug("notification accepted", "request_id", requestID, "status", status, "skill_id", j.Config.SkillID, "device", j.Change.DeviceID)
				n.recovered(j.Config)
				return
			}
			retry = status == 429 || status >= 500 || status >= 200 && status < 300 && !parsed
		}
		if ctx.Err() != nil {
			return
		}
		reason, hint := notificationReason(status, errorCode)
		pauseSeconds, suppressed := 0, uint64(0)
		if status == http.StatusUnauthorized || status == http.StatusForbidden || status == http.StatusNotFound || status == http.StatusBadRequest && errorCode == "UNKNOWN_USER" {
			pauseSeconds = int(notificationCooldown / time.Second)
			suppressed = n.pause(j.Config)
		}
		n.Log.Warn("notification failed", "status", status, "attempt", attempt+1, "device", j.Change.DeviceID, "skill_id", j.Config.SkillID, "user_id", j.Config.UserID, "request_id", requestID, "error_code", errorCode, "reason", reason, "hint", hint, "cooldown_seconds", pauseSeconds, "suppressed", suppressed)
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
