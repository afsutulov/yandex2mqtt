# yandex2mqtt

[Русская версия](README.ru.md)

A bridge between **Yandex Smart Home / Alice** and MQTT. This is a Go
rewrite of [alvlapo/yandex2mqtt](https://gitverse.ru/alvlapo/yandex2mqtt).

The server runs entirely in Go. PostgreSQL, Redis, Node.js and npm are unnecessary
at runtime. Tokens are stored in a local JSON file; Eclipse Paho handles MQTT.

The release includes source, tests, configuration examples and executable binaries
for Linux amd64/arm64, Windows amd64 and macOS arm64 in `bin/`.

## Features

- Yandex availability probe, discovery, query, action and unlink endpoints.
- Browser login and consent; OAuth authorization code, refresh rotation with a
  an idempotent retry window of up to 5 minutes for the previous refresh token, and PKCE S256.
- MQTT 3.1.1 over TCP/TLS/WebSocket, QoS 0/1, automatic reconnect and subscription retry.
- Capabilities: on/off, toggle, range, mode, RGB/HSV/color temperature/scenes.
- Float and event properties, value mappings and relative range commands.
- Per-user device permissions in discovery, query, actions and notifications.
- JSON config and separate JSON device files with strict structural field validation.
- Docker, Compose, systemd and Nginx deployment examples.

## Quick start with a binary

Run the following from the extracted project directory. A working MQTT broker and
your own device topics are required.

```bash
cp config.example.json config.json
chmod 600 config.json
./bin/linux-amd64/yandex2mqtt -hash-password
```

Enter your password at the prompt. Copy the resulting bcrypt hash into
`users[0].passwordHash`. Set a long random OAuth `clientSecret`, your MQTT credentials
and the real device topics. The placeholder password hash intentionally fails
validation. Keep config.json and the token file private.

```bash
./bin/linux-amd64/yandex2mqtt -config config.json -check
./bin/linux-amd64/yandex2mqtt -config config.json
```

Use `bin/linux-arm64/yandex2mqtt` or `bin/darwin-arm64/yandex2mqtt` on those platforms.
On Windows PowerShell:

```powershell
Copy-Item config.example.json config.json
.\bin\windows-amd64\yandex2mqtt.exe -hash-password
.\bin\windows-amd64\yandex2mqtt.exe -config config.json -check
.\bin\windows-amd64\yandex2mqtt.exe -config config.json
```

`-check` validates structure and configuration relationships. It does not connect
to external services or validate their credentials. Configuration changes require
a restart. This release uses one server process per token file, with an OS file lock.

The example enables `http.cookieSecure`. Login requires HTTPS; set it to false only
for local HTTP testing and restore true before public deployment.

## Yandex setup and HTTPS

Expose the service at a public HTTPS URL with a trusted certificate. The Nginx
example in `deploy/nginx.conf.example` proxies to `127.0.0.1:8080`.

| Yandex skill field | Example |
|---|---|
| Endpoint URL | `https://smart.example.ru/provider` |
| Authorization URL | `https://smart.example.ru/dialog/authorize` |
| Token URL | `https://smart.example.ru/oauth/token` |
| Refresh URL | `https://smart.example.ru/oauth/token` |
| Client ID | `clients[].clientId` |
| Client secret | `clients[].clientSecret` |

Register the exact Yandex callback in `clients[].redirectUris`:
`https://social.yandex.net/broker/redirect`. Link the account in the Yandex app, log
in with your local bridge username/password and approve access. Redirects must
match the registered URL exactly; the consent form's CSP permits the origins of
registered HTTPS callbacks.

For TLS served directly by Go:

```json
"http": {"listen": "0.0.0.0:4433", "cookieSecure": true},
"https": {
  "privateKey": "/etc/letsencrypt/live/smart.example.ru/privkey.pem",
  "certificate": "/etc/letsencrypt/live/smart.example.ru/fullchain.pem"
}
```

An external tool such as certbot must obtain and renew the certificate. The bridge
picks up changed certificate/key content on the first TLS handshake after its
one-minute check interval, even when file modification times are preserved.
Malformed, mismatched, expired or not-yet-valid replacements keep the previous
certificate and are logged; a subsequent valid replacement is retried normally.
This does not extend the old certificate's expiry or validate public trust/domain
ownership. An expired/not-yet-valid initial certificate fails startup.

An explicit `http.listen` always wins. When omitted, direct TLS defaults to
`0.0.0.0:4433`, with `https.port` overriding the port; ordinary HTTP defaults to
`127.0.0.1:8080`. Behind an HTTPS proxy omit the `https` block and keep secure cookies.

`HEAD /v1.0`, `/provider/v1.0` and `/provider` return 200 without a token or body.
GET on those three roots also returns 200 without a token. Provider paths
with repeated or trailing slashes are normalized before routing, so POST bodies
and methods survive without a redirect. These probes confirm HTTP endpoint availability. All user-device operations require
a valid Bearer token. `/healthz` checks the process. `/readyz` returns 503 until MQTT
connects and the initial subscription attempt finishes; it reports subscription
counts and `subscriptions.degraded` if some filters need retry. Partial subscription
failure leaves working devices operational.

## Device configuration

`config.example.json` contains five devices adapted from the original: two lights,
a temperature/humidity sensor, a socket with power measurement and a motion sensor.
Additional thermostat, color lamp and incremental IR volume examples are in `examples/`.

Set `"devicesDir": "examples"` to load every `.json` recursively in filename order.
Each file can contain a device object or an array. These extend the inline `devices`
array, so IDs must be unique. Paths are relative to the main config file. Unknown
structural fields are errors, including nested device, feature, binding and mapping
fields. The `parameters` and `device_info` maps remain extensible. Each device file
is limited to 8 MiB and must contain exactly one JSON value.

| Field | Meaning |
|---|---|
| `id` | Stable, unique device ID |
| `allowedUsers` | Local user IDs; an empty array denies everyone |
| `mqtt[].instance` | Feature instance such as on, temperature or motion |
| `mqtt[].type` | Optional full feature type to disambiguate instances |
| `mqtt[].set` | Command topic; sensors need no set topic |
| `mqtt[].state` | Actual state topic; optional for command-only capabilities |
| `mqtt[].confirmTimeoutMs` | 0: publish only; 1–2000: wait for matching fresh state |
| `retrievable` | Include known values in state queries when feedback exists |
| `reportable` | Send incoming changes to Yandex when feedback exists |
| `valueMapping[].type` | Short or full feature type |
| `valueMapping[].instance` | Optional instance filter |
| `valueMapping[].mapping` | `[Yandex values, MQTT values]` |

For example, `[[false,true],[0,1]]` maps a command true to MQTT `1` and incoming
MQTT `1` to true. Numeric JSON mapping values match their MQTT text representation.
Without mappings, booleans accept true/false, on/off or 1/0, case-insensitively.
Numbers must parse completely: `22junk`, NaN and infinity are rejected.
Topics are case-sensitive; wildcard state topics are unsupported. One state topic
may update multiple devices.

**State and commands.** With an MQTT state topic, only incoming telemetry updates
reported state. A set-only capability remains controllable. Without an explicit
initial `state`, discovery marks it `retrievable: false`, `reportable: false`, and
commands do not create reported values.

An explicit initial `state` on a feature without a state topic opts into a
**software estimate**. Query starts with the seed and, when enabled, follows
successfully published absolute commands or incremental deltas. If `reportable`
is enabled, changed estimates also trigger callbacks. A failed publish changes
neither the estimate nor notifications. This is not physical device confirmation;
other controllers or a device ignoring the command can make the estimate wrong.
Use real MQTT feedback when accurate states matter. A restart restores the seed.

Query returns known features and omits unknown ones. A device with readable
features but no known readable values returns DEVICE_UNREACHABLE. A command-only
device can return empty feature arrays without that error.
An absolute-set range without feedback uses the last successfully published target
as its relative-command base, with explicit initial `state` as a fallback. Without
either base a relative command fails with DEVICE_UNREACHABLE. This private cache
is in memory and does not imply state retrieval for an unseeded function.

For a genuinely incremental IR control, explicitly set
`parameters.random_access: false`. Its MQTT set topic receives the signed delta
(e.g. `10` or `-10`), optionally transformed by `valueMapping`. No absolute base is
needed, and `range.min/max` may be omitted. Absolute commands are rejected.
If this control has an explicit initial `state` and no MQTT feedback, deltas also
update the software estimate, bounded by any configured min/max. The MQTT payload
stays a delta. With no seed, no estimate is created.
Use `confirmTimeoutMs: 0`: an increment cannot be confirmed by comparing an
unknown absolute target. DONE confirms the publish, not physical execution.
See `examples/ir-volume.json`; the receiving MQTT/IR adapter must understand those
deltas or map them to its own commands. Existing/default `random_access: true`
set topics continue to receive absolute targets.

Command range values are checked against min/max/precision. Incoming finite range
telemetry is accepted independently: a lamp can report brightness 0 with command
min=1, and a thermostat can report 22.3 even if the command step is 1. Color temperature telemetry also preserves its incoming
nonnegative integer Kelvin value; command bounds default to 2000–9000 K.
Color scenes use `parameters.color_scene.scenes[].id`. Legacy scene `value` keys
are accepted and converted to `id` in discovery.

Relative range results are rounded to the nearest legal step and saturated at
the range boundary. When max is off-grid, the highest permitted step is used.
The default precision is 1; absolute commands remain strict.

With a positive confirmation timeout, DONE requires a new matching message for the
**target feature**. An unrelated measurement cannot confirm stale cached state.
With zero timeout, DONE means the MQTT publish completed: PUBACK at QoS 1, client
send completion at QoS 0. Broker acknowledgement does not prove physical switching.
A command may execute later even after a timeout response.

Different devices in an action batch run concurrently. Capabilities and repeated
entries for the same device execute in request order; response order is preserved.
The HTTP action starts a 2.5-second command budget before decoding its body,
reserving 500ms of Yandex's 3-second end-to-end deadline for transport and encoding.
Network latency and slow request uploads can still exceed the platform deadline.
The budget limits long command
sequences to one device. Requests allow up to 100 device entries and 32 capabilities
per entry.

## Reconnect, ACL and state freshness

The bridge preserves last known states on reconnect by default, including states
published without retain. While MQTT is disconnected, query and commands report
unavailability. After reconnect, cached values can be stale until new telemetry
arrives. Set `mqtt.resetStateOnReconnect: true` to clear bound states instead.
Retained publications are recommended for restoring state after a process restart.

Rejected state subscriptions affect only their bound features. Successful filters
remain active; failed filters retry every two seconds. Query omits inaccessible
read values. Relative commands and commands requiring confirmation fail when their
state subscription is unavailable. Publishing without confirmation is independent
of read permissions and still depends on the broker's publish result.

There is no per-device LWT/availability binding or measurement TTL in this release.
A connected broker alone cannot prove a particular physical device is online.

For MQTT TLS use a URL such as `ssl://broker.example.ru:8883`. Optional `caFile`,
`certFile` and `keyFile` support a custom CA and client certificate. Server certificate
verification remains enabled and TLS 1.2 is the minimum. Give each bridge instance
its own MQTT clientId and token file.

## Login and reverse proxies

Anonymous login pages use a signed CSRF cookie valid for ten minutes and allocate
no server-side session. Successful login creates a new authenticated session.
Cookies are HttpOnly and SameSite=Lax, and Secure when configured.
When password hashes have different bcrypt costs, every authentication performs
one check for each distinct configured cost, substituting the real account hash
in its slot and dummy hashes in all other slots. Unknown users perform the same
work. Existing hashes/passwords remain compatible. Timing has ordinary scheduling
noise; the previous cost-based fourfold distinction is removed. With a uniform
cost, only one bcrypt check is needed.

Login attempts, invalid OAuth client credentials and authenticated grant requests
use separate rate-limit buckets of 30 requests/minute. Grants additionally separate
client, grant type and a hash of the authorization code/refresh token; failed login
traffic cannot consume a valid refresh token's quota. IPv6 peers are grouped by
/64; IPv4 peers by address. At most 10,000 buckets are retained using LRU eviction,
so capacity cannot globally reject every new client. This bounded application
limiter is not protection against a distributed traffic flood. OAuth Basic authentication
accepts both raw credentials and the form-urlencoded variant required by RFC 6749,
including secrets containing plus or percent characters.

By default, client identity comes from the TCP peer and X-Forwarded-For is ignored.
For a local Nginx proxy, explicitly configure trusted proxy CIDRs:

```json
"http": {
  "listen": "127.0.0.1:8080",
  "cookieSecure": true,
  "trustedProxies": ["127.0.0.1/32", "::1/128"]
}
```

The supplied Nginx config appends X-Forwarded-For and sets X-Real-IP.
The latter is a fallback only when X-Forwarded-For is absent and the peer is trusted. The bridge walks the chain from
the right only when the actual peer is trusted. List only your real proxy networks.
Do not use an unrestricted trusted CIDR for a publicly reachable server.

## Refresh retries and upgrading

The previous refresh token can retry for **up to five minutes**, bounded by its
original expiry and the new access token's expiry. Duplicate/concurrent requests
return the same live token pair, including after a process restart. `expires_in`
reports the remaining lifetime, and retries neither extend expiry nor rewrite
the file. Once the new refresh token is used, the older generation stops working.
Client binding and unlink revocation also cover retry records.

Only hashes and a public derivation nonce are stored; bearer tokens are not stored
in plaintext. The previous token supplied by the client acts as the HMAC key for
reconstructing the reply. This grace period is an intentional retry tradeoff for
confidential clients authenticated with their secret, not strict single-use.

Stop 1.2.1, back up `data/tokens.json` and your config, replace the binary and restart.
The token file format remains compatible and current tokens stay valid. An
in-flight 1.2.1 retry record has no nonce: its first old-token retry replaces the
random pair once, preserving the existing deadline; subsequent retries are stable.
If possible, upgrade when no token refresh is in progress. Restoring an old backup
can discard later rotations and require account relinking. Keep both files private.

## Yandex notifications

Add entries to `notification`:

```json
{
  "skill_id": "YOUR_SKILL_ID",
  "oauth_token": "SKILL_OWNER_OAUTH_TOKEN",
  "user_id": "1",
  "client_id": "yandex2mqtt"
}
```

`user_id` is the local provider user ID returned by discovery, not a Yandex account
ID. The notification token belongs to the skill owner for the Dialogs API; it is
separate from the bridge's own access tokens. Specify client_id, especially with
multiple OAuth clients. Features must be reportable; repeated events are delivered.
Device access and active user/client linking are checked before delivery and after
unlink no queued callback for that link is sent.

A 256-message queue and one worker preserve send order. Temporary network errors,
HTTP 429 and 5xx retry up to three attempts. Permanent 4xx responses do not retry.
HTTP status and JSON status=ok are checked. Secrets and request bodies are not logged.
The queue is in memory: restart or overflow can lose notifications; query still
exposes cached state. High telemetry volumes may require a larger persistent queue.

## Migrate a legacy config

Export only your own trusted config.js: Node executes it and its imports.

```bash
node tools/export-config.cjs /opt/old-yandex2mqtt/config.js > legacy.json
./bin/linux-amd64/yandex2mqtt -migrate legacy.json -output config.json
```

The output must not already exist. Migration hashes passwords, adds the Yandex
redirect URL and preserves device IDs, permissions, bindings and mappings. Review
TLS placeholders in the original config and the resulting http.listen. For Nginx
remove the https block. Set real MQTT credentials and secure cookies. Old Loki
files/tokens are not imported: relink accounts.

If a broken legacy room index prevents export, copy the config without its device
import and export device factories directly:

```bash
node tools/export-config.cjs /path/to/config-without-device-import.js /path/to/devices/rooms > legacy.json
```

This skips room index.js files. Review room names in the JSON. On PowerShell 7 use
`Set-Content -Encoding utf8NoBOM` to write the export. Delete legacy.json after a
successful migration because it contains the old plaintext passwords.

Legacy implicit, password and client_credentials grants are available but disabled
by default. Authorization code + refresh is the normal integration. A client-only
token grants no access to user devices.

## Build and test

Install Go **1.26 or later**, with current security patches. There is no vendor
folder. Modules are pinned in go.mod/go.sum and downloaded by Go, normally through
proxy.golang.org and sum.golang.org. The first build requires network access;
subsequent builds can use the module cache. The race detector needs CGO and a C compiler.

```bash
go mod download
go mod build
```

Set GOOS and GOARCH to cross-compile. SHA256SUMS contains hashes of the included
binaries. Dependency downloads are unnecessary when running a provided binary.

## Deployment readiness

1.2.4 is suitable for a single home/small private bridge **after live acceptance**.
Before enabling it, link your actual skill and check discovery, query, a physical
command of each configured type, MQTT disconnect/reconnect, and token refresh.
No live Yandex account or physical equipment was available for this review.
There is no HA token store, durable callback queue, device availability binding or
measurement TTL. Large/public multi-user deployments need those requirements
reviewed separately. Incoming range telemetry stays unchanged; verify values
outside configured command bounds on the real skill instead of silently inventing
a different device state. See [the final review](FINAL-REVIEW.ru.md).

## Protocol references and verification scope

- [Yandex response deadline](https://yandex.ru/dev/dialogs/smart-home/doc/en/start)
- [Yandex availability probe](https://yandex.ru/dev/dialogs/smart-home/doc/en/reference/check)
- [Yandex authorization](https://yandex.ru/dev/dialogs/smart-home/doc/en/auth/how-it-works)
- [Discovery](https://yandex.ru/dev/dialogs/smart-home/doc/en/reference/get-devices)
- [Query](https://yandex.ru/dev/dialogs/smart-home/doc/en/reference/post-devices-query)
- [Actions](https://yandex.ru/dev/dialogs/smart-home/doc/en/reference/post-action)
- [Range capability](https://yandex.ru/dev/dialogs/smart-home/doc/en/concepts/range)
- [OAuth RFC 6749, section 2.3.1](https://www.rfc-editor.org/rfc/rfc6749#section-2.3.1)
- [Eclipse Paho Go](https://pkg.go.dev/github.com/eclipse/paho.mqtt.golang)

Local HTTP/OAuth tests and independent MQTT broker integration tests passed.
Linking your real Yandex skill, public certificates and physical equipment still
requires verification after you fill in your config. Browser CSP headers and
server redirects are tested; the actual Yandex application WebView was not run.
