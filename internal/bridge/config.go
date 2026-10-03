package bridge

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/bcrypt"
)

type Config struct {
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
	Listen       string `json:"listen"`
	Port         int    `json:"port,omitempty"`
	CookieSecure bool   `json:"cookieSecure"`
}
type HTTPSConfig struct {
	PrivateKey  string `json:"privateKey,omitempty"`
	Certificate string `json:"certificate,omitempty"`
	Port        int    `json:"port,omitempty"`
}
type MQTTConfig struct {
	URL       string `json:"url"`
	Host      string `json:"host,omitempty"`
	Port      int    `json:"port,omitempty"`
	User      string `json:"user,omitempty"`
	Password  string `json:"password,omitempty"`
	ClientID  string `json:"clientId"`
	QoS       byte   `json:"qos"`
	TimeoutMS int    `json:"timeoutMs"`
	CAFile    string `json:"caFile,omitempty"`
	CertFile  string `json:"certFile,omitempty"`
	KeyFile   string `json:"keyFile,omitempty"`
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
	SkillID     string `json:"skill_id"`
	Token       string `json:"oauth_token"`
	UserID      string `json:"user_id"`
	LocalUserID string `json:"local_user_id,omitempty"`
	ClientID    string `json:"client_id,omitempty"`
}
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
			b, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			var ds []DeviceConfig
			if strings.HasPrefix(strings.TrimSpace(string(b)), "[") {
				err = json.Unmarshal(b, &ds)
			} else {
				var v DeviceConfig
				err = json.Unmarshal(b, &v)
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
	if c.HTTP.Listen == "" {
		p := c.HTTP.Port
		if p == 0 {
			p = 8080
		}
		if c.HTTPS.Port != 0 {
			p = c.HTTPS.Port
		}
		c.HTTP.Listen = fmt.Sprintf("127.0.0.1:%d", p)
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
func (c Config) Validate() error {
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
					r, ok := f.Parameters["range"].(map[string]any)
					if !ok {
						return fmt.Errorf("range in %s requires min/max", d.ID)
					}
					lo, lok := number(r["min"])
					hi, hok := number(r["max"])
					if !lok || !hok || lo > hi {
						return fmt.Errorf("invalid range in %s", d.ID)
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
	for _, n := range c.Notification {
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
		if n.SkillID == "" || n.Token == "" || n.UserID == "" || !ids[local] || n.ClientID != "" && !ci[n.ClientID] {
			return errors.New("invalid notification identity/credentials")
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
