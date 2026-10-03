package bridge

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"
	"sync"
	"time"
)

type Publisher interface {
	Publish(context.Context, string, []byte) error
	Connected() bool
}
type APIError struct{ Code, Message string }

func (e *APIError) Error() string     { return e.Message }
func apiError(code, msg string) error { return &APIError{code, msg} }
func errorResult(e error) map[string]any {
	code := "INTERNAL_ERROR"
	var a *APIError
	if errors.As(e, &a) {
		code = a.Code
	}
	return map[string]any{"status": "ERROR", "error_code": code, "error_message": e.Error()}
}

type device struct {
	config   DeviceConfig
	mu       sync.RWMutex
	command  chan struct{}
	versions map[string]uint64
	blocked  map[string]bool
	values   map[string]any
	// commanded holds the last accepted command of functions without MQTT
	// feedback. It is never reported as state; it only serves as the base
	// for relative range commands ("louder", "brighter").
	commanded map[string]any
	updated   chan struct{}
}
type Change struct {
	DeviceID                 string
	Capabilities, Properties []map[string]any
}
type Registry struct {
	devices  map[string]*device
	order    []*device
	topics   map[string][]target
	pub      Publisher
	OnChange func(Change)
}
type target struct {
	device  *device
	binding Binding
}

func NewRegistry(c Config, p Publisher) *Registry {
	r := &Registry{devices: map[string]*device{}, topics: map[string][]target{}, pub: p}
	for _, dc := range c.Devices {
		d := &device{config: dc, values: map[string]any{}, commanded: map[string]any{}, versions: map[string]uint64{}, blocked: map[string]bool{}, updated: make(chan struct{}), command: make(chan struct{}, 1)}
		for _, fs := range [][]Feature{dc.Capabilities, dc.Properties} {
			for _, f := range fs {
				if f.State != nil {
					if value, e := normalize(f, f.State.Instance, f.State.Value, false); e == nil {
						d.values[featureKey(f.Type, f.State.Instance)] = clone(value)
					}
				}
			}
		}
		r.devices[dc.ID] = d
		r.order = append(r.order, d)
		for _, b := range dc.MQTT {
			if b.State != "" {
				r.topics[b.State] = append(r.topics[b.State], target{d, b})
			}
		}
	}
	return r
}
func clone(v any) any { b, _ := json.Marshal(v); var x any; _ = json.Unmarshal(b, &x); return x }
func (r *Registry) Topics() []string {
	ts := make([]string, 0, len(r.topics))
	for t := range r.topics {
		ts = append(ts, t)
	}
	return ts
}

// Invalidate is the optional strict reconnect policy. Default reconnects preserve state.
func (r *Registry) Invalidate() {
	for _, d := range r.order {
		d.mu.Lock()
		for _, b := range d.config.MQTT {
			if b.State == "" {
				continue
			}
			for k := range d.values {
				parts := strings.SplitN(k, "|", 2)
				if parts[1] == b.Instance && (b.Type == "" || parts[0] == b.Type) {
					delete(d.values, k)
				}
			}
		}
		close(d.updated)
		d.updated = make(chan struct{})
		d.mu.Unlock()
	}
}
func (r *Registry) HasAccess(user, id string) bool {
	d := r.devices[id]
	return d != nil && contains(d.config.AllowedUsers, user)
}
func (r *Registry) Discovery(user string) []map[string]any {
	out := []map[string]any{}
	for _, d := range r.order {
		if !contains(d.config.AllowedUsers, user) {
			continue
		}
		c := d.config
		m := map[string]any{"id": c.ID, "name": c.Name, "type": c.Type, "capabilities": []map[string]any{}, "properties": []map[string]any{}}
		if c.Room != "" {
			m["room"] = c.Room
		}
		if c.Description != "" {
			m["description"] = c.Description
		}
		if c.DeviceInfo != nil {
			m["device_info"] = c.DeviceInfo
		}
		for _, g := range []struct {
			name string
			fs   []Feature
		}{{"capabilities", c.Capabilities}, {"properties", c.Properties}} {
			arr := []map[string]any{}
			for _, f := range g.fs {
				x := map[string]any{"type": f.Type, "retrievable": f.Retrievable && d.hasFeedback(f), "reportable": f.Reportable && d.hasFeedback(f)}
				if len(f.Parameters) > 0 {
					parameters := clone(f.Parameters).(map[string]any)
					if shortType(f.Type) == "color_setting" {
						if scene, ok := parameters["color_scene"].(map[string]any); ok {
							if values, ok := scene["scenes"].([]any); ok {
								for _, v := range values {
									if m, ok := v.(map[string]any); ok {
										if _, exists := m["id"]; !exists {
											m["id"] = m["value"]
										}
										delete(m, "value")
									}
								}
							}
						}
					}
					x["parameters"] = parameters
				}
				arr = append(arr, x)
			}
			m[g.name] = arr
		}
		out = append(out, m)
	}
	return out
}
func (r *Registry) Query(user, id string) map[string]any {
	m := map[string]any{"id": id}
	if !r.HasAccess(user, id) {
		m["error_code"] = "DEVICE_NOT_FOUND"
		return m
	}
	if !r.pub.Connected() {
		m["error_code"] = "DEVICE_UNREACHABLE"
		return m
	}
	d := r.devices[id]
	expected, known := 0, 0
	d.mu.RLock()
	defer d.mu.RUnlock()
	for _, g := range []struct {
		name string
		fs   []Feature
	}{{"capabilities", d.config.Capabilities}, {"properties", d.config.Properties}} {
		arr := []map[string]any{}
		for _, f := range g.fs {
			if !f.Retrievable || !d.hasFeedback(f) {
				continue
			}
			for _, ins := range featureInstances(f) {
				expected++
				key := featureKey(f.Type, ins)
				v, ok := d.values[key]
				if !ok || d.blocked[key] {
					continue
				}
				known++
				arr = append(arr, stateFeature(f.Type, ins, clone(v)))
			}
		}
		m[g.name] = arr
	}
	if expected > 0 && known == 0 {
		m["error_code"] = "DEVICE_UNREACHABLE"
		delete(m, "capabilities")
		delete(m, "properties")
	}
	return m
}
func (d *device) hasFeedback(f Feature) bool {
	if f.State != nil {
		return true
	}
	for _, ins := range featureInstances(f) {
		if b, ok := d.binding(f.Type, ins); ok && b.State != "" {
			return true
		}
	}
	return false
}

// A rejected read subscription affects only its bound feature, not unrelated devices.
func (r *Registry) SetTopicAvailable(topic string, available bool) {
	for _, target := range r.topics[topic] {
		d, b := target.device, target.binding
		d.mu.Lock()
		for _, fs := range [][]Feature{d.config.Capabilities, d.config.Properties} {
			for _, f := range fs {
				if contains(featureInstances(f), b.Instance) && (b.Type == "" || b.Type == f.Type) {
					d.blocked[featureKey(f.Type, b.Instance)] = !available
				}
			}
		}
		close(d.updated)
		d.updated = make(chan struct{})
		d.mu.Unlock()
	}
}
func stateFeature(t, i string, v any) map[string]any {
	return map[string]any{"type": t, "state": map[string]any{"instance": i, "value": v}}
}
func (d *device) binding(t, i string) (Binding, bool) {
	for _, b := range d.config.MQTT {
		if b.Instance == i && (b.Type == "" || b.Type == t) {
			return b, true
		}
	}
	return Binding{}, false
}
func (d *device) mapped(v any, t, i string, toMQTT bool) any {
	// Instance-specific mappings take priority over legacy type-wide mappings.
	for _, specific := range []bool{true, false} {
		for _, m := range d.config.ValueMapping {
			if m.Type != shortType(t) && m.Type != t {
				continue
			}
			if specific && m.Instance != i || !specific && m.Instance != "" {
				continue
			}
			from, to := 0, 1
			if !toMQTT {
				from, to = 1, 0
			}
			for n, x := range m.Mapping[from] {
				if wire(v) == wire(x) {
					return m.Mapping[to][n]
				}
			}
			return v
		}
	}
	return v
}
func wire(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	b, _ := json.Marshal(v)
	return string(b)
}
func number(v any) (float64, bool) {
	var f float64
	switch x := v.(type) {
	case float64:
		f = x
	case int:
		f = float64(x)
	case json.Number:
		var e error
		f, e = x.Float64()
		if e != nil {
			return 0, false
		}
	case string:
		var e error
		f, e = strconv.ParseFloat(strings.TrimSpace(x), 64)
		if e != nil {
			return 0, false
		}
	default:
		return 0, false
	}
	return f, !math.IsNaN(f) && !math.IsInf(f, 0)
}
func enumValues(v any) []string {
	out := []string{}
	if a, ok := v.([]any); ok {
		for _, item := range a {
			if m, ok := item.(map[string]any); ok {
				if s, ok := m["value"].(string); ok {
					out = append(out, s)
				}
			}
		}
	}
	return out
}
func normalize(f Feature, instance string, v any, command bool) (any, error) {
	bad := func() (any, error) {
		return nil, apiError("INVALID_VALUE", fmt.Sprintf("invalid value for %s", instance))
	}
	switch shortType(f.Type) {
	case "on_off", "toggle":
		if b, ok := v.(bool); ok {
			return b, nil
		}
		if command {
			return bad()
		}
		switch strings.ToLower(strings.TrimSpace(wire(v))) {
		case "true", "on", "1":
			return true, nil
		case "false", "off", "0":
			return false, nil
		}
		return bad()
	case "float", "range":
		if command {
			if _, ok := v.(float64); !ok {
				return bad()
			}
		}
		n, ok := number(v)
		if !ok {
			return bad()
		}
		if command && shortType(f.Type) == "range" {
			ra, _ := f.Parameters["range"].(map[string]any)
			lo, lok := number(ra["min"])
			hi, hok := number(ra["max"])
			if lok && n < lo || hok && n > hi {
				return bad()
			}
			if p := rangePrecision(ra); p > 0 {
				base := lo
				if !lok {
					base = 0
				}
				q := (n - base) / p
				if math.Abs(q-math.Round(q)) > 1e-7 {
					return bad()
				}
			}
		}
		return n, nil
	case "mode", "event":
		s, ok := v.(string)
		if !ok {
			return bad()
		}
		key := "modes"
		if shortType(f.Type) == "event" {
			key = "events"
		}
		if !contains(enumValues(f.Parameters[key]), s) {
			return bad()
		}
		return s, nil
	case "color_setting":
		switch instance {
		case "rgb", "temperature_k":
			if command {
				if _, ok := v.(float64); !ok {
					return bad()
				}
			}
			n, ok := number(v)
			if !ok || n != math.Trunc(n) {
				return bad()
			}
			lo, hi := float64(0), float64(16777215)
			if instance == "temperature_k" {
				p, _ := f.Parameters["temperature_k"].(map[string]any)
				if n < 0 {
					return bad()
				}
				if !command {
					return n, nil
				}
				lo, hi = 2000, 9000
				if v, exists := p["min"]; exists {
					var ok bool
					lo, ok = number(v)
					if !ok {
						return bad()
					}
				}
				if v, exists := p["max"]; exists {
					var ok bool
					hi, ok = number(v)
					if !ok {
						return bad()
					}
				}
			}
			if n < lo || n > hi {
				return bad()
			}
			return n, nil
		case "scene":
			p, _ := f.Parameters["color_scene"].(map[string]any)
			s, ok := v.(string)
			if !ok || !contains(sceneValues(p["scenes"]), s) {
				return bad()
			}
			return s, nil
		case "hsv":
			if s, ok := v.(string); ok && !command {
				var obj map[string]any
				if json.Unmarshal([]byte(s), &obj) != nil {
					return bad()
				}
				v = obj
			}
			m, ok := v.(map[string]any)
			if !ok {
				return bad()
			}
			out := map[string]any{}
			for _, key := range []string{"h", "s", "v"} {
				n, ok := number(m[key])
				max := 100.0
				if key == "h" {
					max = 360
				}
				if !ok || n < 0 || n > max {
					return bad()
				}
				out[key] = n
			}
			return out, nil
		}
	}
	return nil, apiError("INVALID_ACTION", "unsupported feature")
}
func (r *Registry) Update(topic string, payload []byte) []error {
	errs := []error{}
	changes := map[*device]*Change{}
	for _, target := range r.topics[topic] {
		d, b := target.device, target.binding
		change := changes[d]
		if change == nil {
			change = &Change{DeviceID: d.config.ID}
			changes[d] = change
		}
		d.mu.Lock()
		for gi, fs := range [][]Feature{d.config.Capabilities, d.config.Properties} {
			for _, f := range fs {
				if !contains(featureInstances(f), b.Instance) || b.Type != "" && b.Type != f.Type {
					continue
				}
				v := d.mapped(string(payload), f.Type, b.Instance, false)
				val, e := normalize(f, b.Instance, v, false)
				if e != nil {
					errs = append(errs, fmt.Errorf("device %s instance %s: %w", d.config.ID, b.Instance, e))
					continue
				}
				key := featureKey(f.Type, b.Instance)
				old, exists := d.values[key]
				d.values[key] = clone(val)
				d.versions[key]++
				close(d.updated)
				d.updated = make(chan struct{})
				// Events can be repeated; repeated numeric states need no callback.
				if f.Reportable && !d.blocked[key] && (!exists || wire(old) != wire(val) || shortType(f.Type) == "event") {
					cp := stateFeature(f.Type, b.Instance, clone(val))
					if gi == 0 {
						change.Capabilities = append(change.Capabilities, cp)
					} else {
						change.Properties = append(change.Properties, cp)
					}
				}
			}
		}
		d.mu.Unlock()
	}
	if r.OnChange != nil {
		for _, change := range changes {
			if len(change.Capabilities)+len(change.Properties) > 0 {
				r.OnChange(*change)
			}
		}
	}
	return errs
}
func (r *Registry) Act(ctx context.Context, user, id, t string, s State) error {
	if !r.HasAccess(user, id) {
		return apiError("DEVICE_NOT_FOUND", "device does not exist or is not accessible")
	}
	d := r.devices[id]
	select {
	case d.command <- struct{}{}:
		defer func() { <-d.command }()
	case <-ctx.Done():
		return apiError("DEVICE_BUSY", "another command is in progress")
	}
	if ctx.Err() != nil {
		return apiError("DEVICE_UNREACHABLE", "command deadline exceeded")
	}
	var f *Feature
	for i := range d.config.Capabilities {
		c := &d.config.Capabilities[i]
		if c.Type == t && contains(featureInstances(*c), s.Instance) {
			f = c
			break
		}
	}
	if f == nil {
		return apiError("INVALID_ACTION", "capability is not configured")
	}
	b, ok := d.binding(t, s.Instance)
	if !ok || b.Set == "" {
		return apiError("INVALID_ACTION", "MQTT set topic is not configured")
	}
	if incrementalRange(*f) {
		// An IR-style range can only change by a delta. Its command topic
		// takes that signed delta (optionally mapped), not an absolute target.
		if !s.Relative || b.ConfirmTimeoutMS > 0 {
			return apiError("INVALID_ACTION", "incremental range requires a relative command without target confirmation")
		}
		delta, ok := number(s.Value)
		if !ok {
			return apiError("INVALID_VALUE", "relative value must be finite numeric")
		}
		var estimate any
		if b.State == "" && f.State != nil {
			d.mu.RLock()
			current, exists := d.values[featureKey(t, s.Instance)]
			d.mu.RUnlock()
			if n, known := number(current); exists && known {
				next, finite := number(n + delta)
				if !finite {
					return apiError("INVALID_VALUE", "relative estimate must be finite")
				}
				bounds, _ := f.Parameters["range"].(map[string]any)
				if lo, known := number(bounds["min"]); known {
					next = math.Max(lo, next)
				}
				if hi, known := number(bounds["max"]); known {
					next = math.Min(hi, next)
				}
				estimate = next
			}
		}
		if !r.pub.Connected() {
			return apiError("DEVICE_UNREACHABLE", "MQTT disconnected")
		}
		if err := r.pub.Publish(ctx, b.Set, []byte(wire(d.mapped(delta, t, s.Instance, true)))); err != nil {
			return apiError("DEVICE_UNREACHABLE", "MQTT publish failed or timed out")
		}
		if estimate != nil {
			r.commitSetOnly(d, *f, s.Instance, estimate, false)
		}
		return nil
	}
	key := featureKey(t, s.Instance)
	d.mu.RLock()
	blocked := d.blocked[key]
	d.mu.RUnlock()
	if blocked && (s.Relative || b.ConfirmTimeoutMS > 0) {
		return apiError("DEVICE_UNREACHABLE", "state subscription unavailable")
	}
	v := s.Value
	if s.Relative {
		if shortType(t) != "range" {
			return apiError("INVALID_ACTION", "relative is supported only for range")
		}
		delta, ok := v.(float64)
		if !ok {
			return apiError("INVALID_VALUE", "relative value must be numeric")
		}
		d.mu.RLock()
		cur, exists := d.values[key]
		if b.State == "" {
			// Without feedback Yandex sends "louder/brighter" as relative
			// commands; the last command sent by the bridge is the only base.
			if last, sent := d.commanded[key]; sent {
				cur, exists = last, true
			}
		}
		d.mu.RUnlock()
		n, ok := number(cur)
		if !ok || !exists {
			return apiError("DEVICE_UNREACHABLE", "current state is unknown")
		}
		if _, finite := number(delta); !finite {
			return apiError("INVALID_VALUE", "relative value must be finite")
		}
		result := n + delta
		if _, finite := number(result); !finite {
			return apiError("INVALID_VALUE", "relative result must be finite")
		}
		v = clampRelativeRange(*f, result)
	}
	value, e := normalize(*f, s.Instance, v, true)
	if e != nil {
		return e
	}
	if !r.pub.Connected() {
		return apiError("DEVICE_UNREACHABLE", "MQTT disconnected")
	}
	timeout := time.Duration(b.ConfirmTimeoutMS) * time.Millisecond
	// Subscribe to updates before publishing, so a fast state echo cannot be missed.
	d.mu.RLock()
	wake := d.updated
	version := d.versions[key]
	d.mu.RUnlock()
	if e = r.pub.Publish(ctx, b.Set, []byte(wire(d.mapped(value, t, s.Instance, true)))); e != nil {
		return apiError("DEVICE_UNREACHABLE", "MQTT publish failed or timed out")
	}
	if timeout > 0 {
		timer := time.NewTimer(timeout)
		defer timer.Stop()
		observed := false
		for {
			if observed {
				d.mu.RLock()
				actual, exists := d.values[key]
				fresh := d.versions[key] > version && !d.blocked[key]
				wake = d.updated
				d.mu.RUnlock()
				if exists && fresh && wire(actual) == wire(value) {
					return nil
				}
			}
			select {
			case <-wake:
				observed = true
			case <-timer.C:
				return apiError("DEVICE_UNREACHABLE", "no matching MQTT state confirmation")
			case <-ctx.Done():
				return apiError("DEVICE_UNREACHABLE", "command cancelled")
			}
		}
	}
	if b.State == "" {
		r.commitSetOnly(d, *f, s.Instance, value, true)
	}
	return nil
}

// An explicit initial state opts a set-only feature into a software estimate.
// The estimate is not MQTT feedback. Commit only after successful publication,
// notify reportable changes outside the state lock, and never create an estimate
// for a feature without an explicitly configured seed.
func (r *Registry) commitSetOnly(d *device, f Feature, instance string, value any, remember bool) {
	key := featureKey(f.Type, instance)
	var change *Change
	d.mu.Lock()
	if remember {
		d.commanded[key] = clone(value)
	}
	if old, readable := d.values[key]; readable && f.State != nil {
		d.values[key] = clone(value)
		d.versions[key]++
		close(d.updated)
		d.updated = make(chan struct{})
		if f.Reportable && !d.blocked[key] && wire(old) != wire(value) {
			change = &Change{DeviceID: d.config.ID, Capabilities: []map[string]any{stateFeature(f.Type, instance, clone(value))}}
		}
	}
	d.mu.Unlock()
	if change != nil && r.OnChange != nil {
		r.OnChange(*change)
	}
}

func incrementalRange(f Feature) bool {
	return shortType(f.Type) == "range" && f.Parameters["random_access"] == false
}

// Relative controls saturate at the nearest legal step. Telemetry stays unchanged.
func clampRelativeRange(f Feature, n float64) float64 {
	ra, _ := f.Parameters["range"].(map[string]any)
	lo, _ := number(ra["min"])
	hi, _ := number(ra["max"])
	n = math.Max(lo, math.Min(hi, n))
	if p := rangePrecision(ra); p > 0 {
		// Limit the step index before reconstructing; max need not fall on the grid.
		maxStep := math.Floor((hi-lo)/p + 1e-9)
		step := math.Max(0, math.Min(maxStep, math.Round((n-lo)/p)))
		n = lo + step*p
	}
	return math.Max(lo, math.Min(hi, n))
}
func sceneValues(v any) []string {
	out := []string{}
	if a, ok := v.([]any); ok {
		for _, x := range a {
			if m, ok := x.(map[string]any); ok {
				id, _ := m["id"].(string)
				if id == "" {
					id, _ = m["value"].(string)
				}
				if id != "" {
					out = append(out, id)
				}
			}
		}
	}
	return out
}

func rangePrecision(ra map[string]any) float64 {
	if v, exists := ra["precision"]; exists {
		n, _ := number(v)
		return n
	}
	return 1
}
