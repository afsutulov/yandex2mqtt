package bridge

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/bcrypt"
)

type Config struct {
	Logging      LoggingConfig        `json:"logging,omitempty"`
	HTTP         HTTPConfig           `json:"http"`
	HTTPS        HTTPSConfig          `json:"https,omitempty"`
	MQTT         MQTTConfig           `json:"mqtt"`
	OAuth        OAuthConfig          `json:"oauth"`
	Users        []User               `json:"users"`
	Clients      []Client             `json:"clients"`
	Devices      []DeviceConfig       `json:"devices"`
	DevicesDir   string               `json:"devicesDir,omitempty"`
	Notification []NotificationConfig `json:"notification,omitempty"`
	DataFile     string               `json:"dataFile"`
}
type HTTPConfig struct {
	TrustedProxies []string `json:"trustedProxies,omitempty"`
	Listen         string   `json:"listen"`
	Port           int      `json:"port,omitempty"`
	CookieSecure   bool     `json:"cookieSecure"`
}
type HTTPSConfig struct {
	PrivateKey  string `json:"privateKey,omitempty"`
	Certificate string `json:"certificate,omitempty"`
	Port        int    `json:"port,omitempty"`
}
type MQTTConfig struct {
	ResetStateOnReconnect bool   `json:"resetStateOnReconnect,omitempty"`
	URL                   string `json:"url"`
	Host                  string `json:"host,omitempty"`
	Port                  int    `json:"port,omitempty"`
	User                  string `json:"user,omitempty"`
	Password              string `json:"password,omitempty"`
	ClientID              string `json:"clientId"`
	QoS                   byte   `json:"qos"`
	TimeoutMS             int    `json:"timeoutMs"`
	CAFile                string `json:"caFile,omitempty"`
	CertFile              string `json:"certFile,omitempty"`
	KeyFile               string `json:"keyFile,omitempty"`
}
type OAuthConfig struct {
	AccessTTL              int  `json:"accessTokenTTLSeconds"`
	RefreshTTL             int  `json:"refreshTokenTTLSeconds"`
	CodeTTL                int  `json:"codeTTLSeconds"`
	AllowPassword          bool `json:"allowPasswordGrant,omitempty"`
	AllowImplicit          bool `json:"allowImplicitGrant,omitempty"`
	AllowClientCredentials bool `json:"allowClientCredentialsGrant,omitempty"`
}
type User struct {
	ID           string `json:"id"`
	Username     string `json:"username"`
	Name         string `json:"name"`
	Password     string `json:"password,omitempty"`
	PasswordHash string `json:"passwordHash,omitempty"`
}
type Client struct {
	ID           string   `json:"id"`
	Name         string   `json:"name"`
	ClientID     string   `json:"clientId"`
	Secret       string   `json:"clientSecret"`
	Trusted      bool     `json:"isTrusted"`
	RedirectURIs []string `json:"redirectUris"`
}
type NotificationConfig struct {
	Enabled     *bool  `json:"enabled,omitempty"`
	SkillID     string `json:"skill_id"`
	Token       string `json:"oauth_token"`
	UserID      string `json:"user_id"`
	LocalUserID string `json:"local_user_id,omitempty"`
	ClientID    string `json:"client_id,omitempty"`
}

func (n NotificationConfig) enabled() bool { return n.Enabled == nil || *n.Enabled }

type DeviceConfig struct {
	ID           string         `json:"id"`
	Name         string         `json:"name"`
	Description  string         `json:"description,omitempty"`
	Room         string         `json:"room,omitempty"`
	Type         string         `json:"type"`
	DeviceInfo   map[string]any `json:"device_info,omitempty"`
	AllowedUsers []string       `json:"allowedUsers"`
	MQTT         []Binding      `json:"mqtt"`
	ValueMapping []ValueMapping `json:"valueMapping,omitempty"`
	Capabilities []Feature      `json:"capabilities,omitempty"`
	Properties   []Feature      `json:"properties,omitempty"`
}
type Binding struct {
	Instance         string `json:"instance"`
	Type             string `json:"type,omitempty"`
	Set              string `json:"set,omitempty"`
	State            string `json:"state,omitempty"`
	ConfirmTimeoutMS int    `json:"confirmTimeoutMs,omitempty"`
}
type ValueMapping struct {
	Type     string  `json:"type"`
	Instance string  `json:"instance,omitempty"`
	Mapping  [][]any `json:"mapping"`
}
type Feature struct {
	Type        string         `json:"type"`
	Retrievable bool           `json:"retrievable"`
	Reportable  bool           `json:"reportable"`
	Parameters  map[string]any `json:"parameters,omitempty"`
	State       *State         `json:"state,omitempty"`
}
type State struct {
	Instance string `json:"instance"`
	Value    any    `json:"value"`
	Relative bool   `json:"relative,omitempty"`
}

func LoadConfig(path string) (Config, error) {
	var c Config
	f, e := os.Open(path)
	if e != nil {
		return c, e
	}
	defer f.Close()
	dec := json.NewDecoder(io.LimitReader(f, 8<<20))
	dec.DisallowUnknownFields()
	if e = dec.Decode(&c); e != nil {
		return c, fmt.Errorf("config: %w", e)
	}
	if dec.Decode(new(any)) != io.EOF {
		return c, errors.New("config must contain one JSON object")
	}
	base := filepath.Dir(path)
	resolve := func(p string) string {
		if p != "" && !filepath.IsAbs(p) {
			return filepath.Join(base, p)
		}
		return p
	}
	c.DataFile = resolve(c.DataFile)
	c.DevicesDir = resolve(c.DevicesDir)
	c.HTTPS.PrivateKey = resolve(c.HTTPS.PrivateKey)
	c.HTTPS.Certificate = resolve(c.HTTPS.Certificate)
	c.MQTT.CAFile = resolve(c.MQTT.CAFile)
	c.MQTT.CertFile = resolve(c.MQTT.CertFile)
	c.MQTT.KeyFile = resolve(c.MQTT.KeyFile)
	if c.DevicesDir != "" {
		e = filepath.WalkDir(c.DevicesDir, func(p string, d os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() || !strings.HasSuffix(d.Name(), ".json") {
				return nil
			}
			f, err := os.Open(p)
			if err != nil {
				return err
			}
			b, err := io.ReadAll(io.LimitReader(f, (8<<20)+1))
			closeErr := f.Close()
			if err != nil {
				return err
			}
			if closeErr != nil {
				return closeErr
			}
			var ds []DeviceConfig
			if len(b) > 8<<20 {
				return fmt.Errorf("devices file %s exceeds 8 MiB", p)
			}
			if strings.HasPrefix(strings.TrimSpace(string(b)), "[") {
				err = decodeStrictJSON(b, &ds)
			} else {
				var v DeviceConfig
				err = decodeStrictJSON(b, &v)
				ds = []DeviceConfig{v}
			}
			if err != nil {
				return fmt.Errorf("devices file %s: %w", p, err)
			}
			c.Devices = append(c.Devices, ds...)
			return nil
		})
		if e != nil {
			return c, e
		}
	}
	if c.DataFile == "" {
		c.DataFile = filepath.Join(base, "data", "tokens.json")
	}
	c.Defaults()
	return c, c.Validate()
}
func (c *Config) Defaults() {
	c.Logging.Level = strings.ToLower(strings.TrimSpace(c.Logging.Level))
	if c.Logging.Level == "" {
		c.Logging.Level = "info"
	}
	if c.HTTP.Listen == "" {
		p := c.HTTP.Port
		if p == 0 {
			p = 8080
		}
		if c.HTTPS.Port != 0 {
			p = c.HTTPS.Port
		}
		host := "127.0.0.1"
		if c.HTTPS.Certificate != "" {
			host = "0.0.0.0"
			if c.HTTP.Port == 0 && c.HTTPS.Port == 0 {
				p = 4433
			}
		}
		c.HTTP.Listen = fmt.Sprintf("%s:%d", host, p)
	}
	if c.HTTPS.Certificate != "" {
		c.HTTP.CookieSecure = true
	}
	if c.MQTT.URL == "" {
		h := c.MQTT.Host
		if h == "" {
			h = "localhost"
		}
		p := c.MQTT.Port
		if p == 0 {
			p = 1883
		}
		c.MQTT.URL = fmt.Sprintf("tcp://%s:%d", h, p)
	}
	if c.MQTT.ClientID == "" {
		c.MQTT.ClientID = "yandex2mqtt-go"
	}
	if c.MQTT.TimeoutMS == 0 {
		c.MQTT.TimeoutMS = 1500
	}
	if c.OAuth.AccessTTL == 0 {
		c.OAuth.AccessTTL = 86400
	}
	if c.OAuth.RefreshTTL == 0 {
		c.OAuth.RefreshTTL = 90 * 86400
	}
	if c.OAuth.CodeTTL == 0 {
		c.OAuth.CodeTTL = 300
	}
	for i := range c.Devices {
		d := &c.Devices[i]
		if d.ID == "" {
			d.ID = fmt.Sprint(i)
		}
		if d.Name == "" {
			d.Name = "Без названия"
		}
		if d.Type == "" {
			d.Type = "devices.types.light"
		}
		if d.AllowedUsers == nil {
			d.AllowedUsers = []string{"1"}
		}
	}
}
func decodeStrictJSON(b []byte, out any) error {
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if e := d.Decode(out); e != nil {
		return e
	}
	if d.Decode(new(any)) != io.EOF {
		return errors.New("one JSON value required")
	}
	return nil
}
func (c Config) Validate() error {
	if _, e := c.Logging.ParseLevel(); e != nil {
		return e
	}
	for _, raw := range c.HTTP.TrustedProxies {
		if _, e := netip.ParsePrefix(raw); e != nil {
			return fmt.Errorf("invalid trusted proxy CIDR %q", raw)
		}
	}
	if len(c.Users) == 0 || len(c.Clients) == 0 {
		return errors.New("at least one user and OAuth client required")
	}
	ids := map[string]bool{}
	names := map[string]bool{}
	for _, u := range c.Users {
		if u.ID == "" || u.Username == "" || ids[u.ID] || names[u.Username] {
			return errors.New("user id/username empty or duplicate")
		}
		ids[u.ID] = true
		names[u.Username] = true
		if u.PasswordHash != "" {
			cost, e := bcrypt.Cost([]byte(u.PasswordHash))
			if e != nil || cost < 10 || cost > 16 {
				return fmt.Errorf("user %s: bcrypt cost must be 10..16", u.ID)
			}
		} else if u.Password == "" {
			return fmt.Errorf("user %s has no password", u.ID)
		}
		if len(u.Password) > 72 {
			return errors.New("password too long (bcrypt limit: 72 bytes)")
		}
	}
	ci := map[string]bool{}
	internal := map[string]bool{}
	for _, x := range c.Clients {
		if x.ID == "" || x.ClientID == "" || x.Secret == "" || ci[x.ClientID] || internal[x.ID] {
			return errors.New("OAuth client fields empty or duplicate")
		}
		ci[x.ClientID] = true
		internal[x.ID] = true
		if len(x.RedirectURIs) == 0 {
			return fmt.Errorf("client %s requires redirectUris", x.ClientID)
		}
		for _, raw := range x.RedirectURIs {
			u, e := url.Parse(raw)
			if e != nil || u.Scheme != "https" || u.Host == "" || u.Fragment != "" || u.User != nil {
				return fmt.Errorf("client %s: redirect URI must be absolute HTTPS without fragment/userinfo", x.ClientID)
			}
		}
	}
	u, e := url.Parse(c.MQTT.URL)
	if e != nil || u.Host == "" || !contains([]string{"tcp", "ssl", "tls", "mqtt", "mqtts", "ws", "wss"}, u.Scheme) {
		return errors.New("invalid MQTT URL")
	}
	if c.MQTT.QoS > 1 {
		return errors.New("MQTT qos must be 0 or 1")
	}
	if c.MQTT.TimeoutMS < 100 || c.MQTT.TimeoutMS > 3000 {
		return errors.New("MQTT timeoutMs must be 100..3000")
	}
	if (c.MQTT.CertFile == "") != (c.MQTT.KeyFile == "") {
		return errors.New("both MQTT certFile and keyFile are required")
	}
	if (c.HTTPS.PrivateKey == "") != (c.HTTPS.Certificate == "") {
		return errors.New("both HTTPS privateKey and certificate required")
	}
	if c.OAuth.AccessTTL < 60 || c.OAuth.RefreshTTL < c.OAuth.AccessTTL || c.OAuth.CodeTTL < 30 || c.OAuth.CodeTTL > 600 {
		return errors.New("invalid OAuth TTL")
	}
	dids := map[string]bool{}
	for _, d := range c.Devices {
		if dids[d.ID] {
			return fmt.Errorf("duplicate device %s", d.ID)
		}
		dids[d.ID] = true
		for _, id := range d.AllowedUsers {
			if !ids[id] {
				return fmt.Errorf("device %s has unknown allowedUser %s", d.ID, id)
			}
		}
		keys := map[string]bool{}
		for gi, group := range [][]Feature{d.Capabilities, d.Properties} {
			for _, f := range group {
				if !(strings.HasPrefix(f.Type, "devices.capabilities.") || strings.HasPrefix(f.Type, "devices.properties.")) {
					return fmt.Errorf("device %s: invalid feature type", d.ID)
				}
				kind := shortType(f.Type)
				if gi == 0 && (!strings.HasPrefix(f.Type, "devices.capabilities.") || kind == "float" || kind == "event") || gi == 1 && (!strings.HasPrefix(f.Type, "devices.properties.") || (kind != "float" && kind != "event")) {
					return fmt.Errorf("device %s: feature placed in wrong capabilities/properties group", d.ID)
				}
				if !contains([]string{"on_off", "toggle", "range", "mode", "color_setting", "float", "event"}, kind) {
					return fmt.Errorf("unsupported feature %s", f.Type)
				}
				instances := featureInstances(f)
				if len(instances) == 0 {
					return fmt.Errorf("device %s: %s requires parameters.instance or color model", d.ID, f.Type)
				}
				for _, ins := range instances {
					k := featureKey(f.Type, ins)
					if keys[k] {
						return fmt.Errorf("duplicate feature %s", k)
					}
					keys[k] = true
				}
				if kind == "range" {
					if raw, exists := f.Parameters["random_access"]; exists {
						if _, ok := raw.(bool); !ok {
							return fmt.Errorf("random_access must be boolean in %s", d.ID)
						}
					}
					r, ok := f.Parameters["range"].(map[string]any)
					_, supplied := f.Parameters["range"]
					if !ok && (supplied || !incrementalRange(f)) {
						return fmt.Errorf("range in %s requires min/max", d.ID)
					}
					lo, lok := number(r["min"])
					hi, hok := number(r["max"])
					if !incrementalRange(f) && (!lok || !hok) || lok && hok && (lo > hi || math.IsInf(hi-lo, 0)) {
						return fmt.Errorf("invalid range in %s", d.ID)
					}
					for _, key := range []string{"min", "max"} {
						if raw, exists := r[key]; exists {
							if _, ok := number(raw); !ok {
								return fmt.Errorf("invalid range %s in %s", key, d.ID)
							}
						}
					}
					if v, exists := r["precision"]; exists {
						precision, ok := number(v)
						if !ok || precision <= 0 || lok && hok && math.IsInf((hi-lo)/precision, 0) {
							return fmt.Errorf("invalid range precision in %s", d.ID)
						}
					}
					if incrementalRange(f) {
						for _, b := range d.MQTT {
							if b.Instance == instances[0] && (b.Type == "" || b.Type == f.Type) && b.ConfirmTimeoutMS > 0 {
								return fmt.Errorf("device %s: incremental range requires confirmTimeoutMs=0", d.ID)
							}
						}
					}
				}
				if kind == "color_setting" {
					if raw, exists := f.Parameters["color_model"]; exists {
						model, ok := raw.(string)
						if !ok || model != "rgb" && model != "hsv" {
							return fmt.Errorf("invalid color_model in %s", d.ID)
						}
					}
					if raw, exists := f.Parameters["temperature_k"]; exists {
						params, ok := raw.(map[string]any)
						if !ok {
							return fmt.Errorf("invalid temperature_k in %s", d.ID)
						}
						lo, hi := 2000.0, 9000.0
						for key, target := range map[string]*float64{"min": &lo, "max": &hi} {
							if v, exists := params[key]; exists {
								n, ok := number(v)
								if !ok || n < 0 || n != math.Trunc(n) {
									return fmt.Errorf("invalid temperature_k %s in %s", key, d.ID)
								}
								*target = n
							}
						}
						if lo > hi {
							return fmt.Errorf("invalid temperature_k range in %s", d.ID)
						}
					}
					if raw, exists := f.Parameters["color_scene"]; exists {
						scene, ok := raw.(map[string]any)
						if !ok || len(sceneValues(scene["scenes"])) == 0 {
							return fmt.Errorf("color_scene requires scene IDs in %s", d.ID)
						}
					}
				}
				if kind == "mode" || kind == "event" {
					field := "modes"
					if kind == "event" {
						field = "events"
					}
					if len(enumValues(f.Parameters[field])) == 0 {
						return fmt.Errorf("%s requires %s", f.Type, field)
					}
				}
				if f.State != nil {
					if !contains(instances, f.State.Instance) {
						return fmt.Errorf("invalid initial instance in %s", d.ID)
					}
					if _, err := normalize(f, f.State.Instance, f.State.Value, false); err != nil {
						return fmt.Errorf("invalid initial state in %s: %w", d.ID, err)
					}
				}
			}
		}
		bound := map[string]bool{}
		for _, b := range d.MQTT {
			if b.Instance == "" || b.Set == "" && b.State == "" {
				return fmt.Errorf("device %s: empty MQTT binding", d.ID)
			}
			if strings.ContainsAny(b.Set+b.State, "+#\x00") {
				return errors.New("only exact MQTT topics supported; wildcards/NUL forbidden")
			}
			if b.ConfirmTimeoutMS < 0 || b.ConfirmTimeoutMS > 2000 || b.ConfirmTimeoutMS > 0 && b.State == "" {
				return errors.New("confirmTimeoutMs must be 0..2000 and requires state topic")
			}
			matches := 0
			for k := range keys {
				parts := strings.SplitN(k, "|", 2)
				if parts[1] == b.Instance && (b.Type == "" || b.Type == parts[0]) {
					matches++
					if bound[k] {
						return fmt.Errorf("duplicate binding for %s", k)
					}
					bound[k] = true
				}
			}
			if matches == 0 {
				return fmt.Errorf("device %s: binding %s matches no feature", d.ID, b.Instance)
			}
		}
		for _, m := range d.ValueMapping {
			if len(m.Mapping) != 2 || len(m.Mapping[0]) == 0 || len(m.Mapping[0]) != len(m.Mapping[1]) {
				return fmt.Errorf("device %s: invalid valueMapping", d.ID)
			}
			for side := 0; side < 2; side++ {
				seen := map[string]bool{}
				for _, v := range m.Mapping[side] {
					k := wire(v)
					if seen[k] {
						return fmt.Errorf("device %s: ambiguous mapping value %s", d.ID, k)
					}
					seen[k] = true
				}
			}
		}
	}
	for i, n := range c.Notification {
		if !n.enabled() {
			continue
		}
		if n.SkillID == "" || !validSkillID(n.SkillID) {
			return fmt.Errorf("notification[%d].skill_id must contain only letters, digits, hyphens or underscores; copy the ID, not a URL", i)
		}
		if strings.HasSuffix(n.SkillID, "-draft") {
			return fmt.Errorf("notification[%d].skill_id refers to a draft: publish the skill (private publication is sufficient) and copy its published ID", i)
		}
		if n.Token == "" || strings.ContainsAny(n.Token, " \t\r\n") {
			return fmt.Errorf("notification[%d].oauth_token must be the skill owner's Dialogs OAuth token without whitespace", i)
		}
		if len(c.Clients) > 1 && n.ClientID == "" {
			return errors.New("notification.client_id required when multiple OAuth clients are configured")
		}
		if n.LocalUserID != "" && n.LocalUserID != n.UserID {
			return errors.New("notification.user_id must equal the provider user ID from discovery")
		}
		local := n.LocalUserID
		if local == "" {
			local = n.UserID
		}
		if n.UserID == "" || !ids[local] {
			return fmt.Errorf("notification[%d].user_id must match users[].id and the ID returned by discovery", i)
		}
		if n.ClientID != "" && !ci[n.ClientID] {
			return fmt.Errorf("notification[%d].client_id must match clients[].clientId", i)
		}
	}
	return nil
}
func contains(xs []string, s string) bool {
	for _, v := range xs {
		if v == s {
			return true
		}
	}
	return false
}
func shortType(t string) string     { p := strings.Split(t, "."); return p[len(p)-1] }
func featureKey(t, i string) string { return t + "|" + i }
func featureInstances(f Feature) []string {
	if shortType(f.Type) == "on_off" {
		return []string{"on"}
	}
	if shortType(f.Type) == "color_setting" {
		out := []string{}
		if m, _ := f.Parameters["color_model"].(string); m == "rgb" || m == "hsv" {
			out = append(out, m)
		}
		if _, ok := f.Parameters["temperature_k"]; ok {
			out = append(out, "temperature_k")
		}
		if _, ok := f.Parameters["color_scene"]; ok {
			out = append(out, "scene")
		}
		return out
	}
	if i, _ := f.Parameters["instance"].(string); i != "" {
		return []string{i}
	}
	return nil
}

func validSkillID(s string) bool {
	if len(s) == 0 || len(s) > 256 {
		return false
	}
	for _, ch := range s {
		if !(ch >= 'a' && ch <= 'z' || ch >= 'A' && ch <= 'Z' || ch >= '0' && ch <= '9' || ch == '-' || ch == '_') {
			return false
		}
	}
	return true
}
