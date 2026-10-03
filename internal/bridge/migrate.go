package bridge

import (
	"encoding/json"
	"fmt"
	"os"

	"golang.org/x/crypto/bcrypt"
)

// Migrate consumes inert JSON exported by the optional Node.js helper.
// Go itself never executes an old JavaScript configuration.
func Migrate(input, output string) error {
	b, e := os.ReadFile(input)
	if e != nil {
		return e
	}
	var c Config
	if e = json.Unmarshal(b, &c); e != nil {
		return e
	}
	c.Defaults()
	c.MQTT.QoS = 1
	if c.DataFile == "" {
		c.DataFile = "data/tokens.json"
	}
	for i := range c.Users {
		u := &c.Users[i]
		if u.PasswordHash == "" {
			if u.Password == "" {
				return fmt.Errorf("user %s has no password", u.ID)
			}
			h, e := bcrypt.GenerateFromPassword([]byte(u.Password), 12)
			if e != nil {
				return e
			}
			u.PasswordHash = string(h)
		}
		u.Password = ""
	}
	for i := range c.Clients {
		if len(c.Clients[i].RedirectURIs) == 0 {
			c.Clients[i].RedirectURIs = []string{"https://social.yandex.net/broker/redirect"}
		}
	}
	if len(c.Notification) > 0 {
		if len(c.Clients) == 1 {
			for i := range c.Notification {
				if c.Notification[i].ClientID == "" {
					c.Notification[i].ClientID = c.Clients[0].ClientID
				}
			}
		}
		for i := range c.Devices {
			d := &c.Devices[i]
			for j := range d.Capabilities {
				d.Capabilities[j].Reportable = hasStateBinding(*d, d.Capabilities[j])
			}
			for j := range d.Properties {
				d.Properties[j].Reportable = hasStateBinding(*d, d.Properties[j])
			}
		}
	}
	if e = c.Validate(); e != nil {
		return e
	}
	b, e = json.MarshalIndent(c, "", "  ")
	if e != nil {
		return e
	}
	// Refuse to silently overwrite an existing configuration.
	f, e := os.OpenFile(output, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if e != nil {
		return e
	}
	defer f.Close()
	_, e = f.Write(append(b, '\n'))
	return e
}
func hasStateBinding(d DeviceConfig, f Feature) bool {
	for _, b := range d.MQTT {
		if b.State != "" && contains(featureInstances(f), b.Instance) && (b.Type == "" || b.Type == f.Type) {
			return true
		}
	}
	return false
}
