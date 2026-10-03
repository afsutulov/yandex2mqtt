# Changelog

## 1.2.4 — 2026-10-03

- Equalize bcrypt work for mixed-cost accounts and unknown usernames without
  changing existing passwords/hashes. Uniform-cost deployments still need one check.
- Emit configured callbacks when seeded set-only software estimates change;
  incremental IR commands also update an explicit estimate without changing
  their signed-delta MQTT payload or inventing a state for unseeded functions.
- Detect TLS renewal by certificate/key content instead of modification times.
- Reject expired/not-yet-valid TLS replacements, preserve the previously
  accepted certificate on failure, and accept later valid replacements.
- Clarify software estimates, externally managed certificate renewal, timing
  protection and readiness scope in both READMEs and FINAL-REVIEW.ru.md.
- Add five regression functions (66 total), rebuild four binaries and update hashes.

## 1.2.3 — 2026-10-03

- A command-only function with explicit initial `state` (advertised as readable)
  now reports the last successfully published value; 1.2.2 reported the initial
  value forever, contradicting the command Alice had just executed.
- The dummy bcrypt hash for unknown usernames uses the same cost as real hashes;
  1.2.2 used cost 10 against cost 12, so response time revealed valid usernames.
- Direct TLS reloads renewed certificate files without a restart (checked at most
  once a minute; a broken renewal keeps the last valid certificate).
- Three regression tests added (61 test functions). See REVIEW-1.2.3.ru.md.

## 1.2.2 — 2026-10-03

- Return the same access/refresh pair for duplicate refresh requests, including
  concurrent retries and restart, using HMAC derivation without plaintext tokens.
- Bound retry grace by the original refresh expiry and new access expiry; report
  remaining access lifetime and avoid file writes on idempotent retries.
- Upgrade existing 1.2.1 grace records on their first retry without extending grace.
- Use bounded LRU rate buckets instead of globally denying new clients at capacity;
  preserve IPv6 /64 grouping and separate login/OAuth scopes.
- Reduce the action budget to 2.5 seconds to leave transport time within Yandex
  Smart Home's documented 3-second end-to-end deadline.
- Use the latest successfully published command rather than static initial state
  as the relative base for absolute-set capabilities without MQTT feedback.
- Support incremental ranges (`random_access: false`): publish signed deltas
  without requiring an absolute base or range bounds, with optional value mapping.
  Target confirmation must be disabled for these controls.
- Add nine production regression/upgrade checks (58 test functions in total),
  update both READMEs, include an IR example and a detailed production review.
- Rebuild all four binaries and update SHA256SUMS. No vendor directory.

## 1.2.1 — 2026-10-03

- Relative range commands for command-only capabilities (IR-style volume,
  brightness without feedback) use the last absolute command sent by the bridge;
  1.2.0 always answered DEVICE_UNREACHABLE. The base is never reported as state.
- The previous refresh token stays valid for 5 minutes after rotation. A retry
  after a lost refresh response supersedes the lost pair instead of breaking the
  account link. The window is persisted and bound to the client.
- Rate-limit keys group IPv6 clients by /64, so one host cannot fill the table
  and lock everyone out of the login form.
- Two existing tests adapted to the refresh retry window; three regression tests
  added. See REVIEW-1.2.1.ru.md.

## 1.2.0 — 2026-10-03

- Combined independent 1.0.1 fixes with 1.1.0; documented the behavioral choices.
- Added provider path normalization without POST redirects and public root GET probes.
- Saturate relative range commands at the nearest legal step, including off-grid maxima.
- Preserve inbound Kelvin telemetry independently of command limits.
- Recover action-entry panics while preserving repeated-device order.
- Support X-Real-IP only as a fallback from an explicitly trusted proxy.
- Correct color scene IDs and apply default Kelvin bounds and default range precision.
- Include twelve imported regression functions and five new merge checks.
- Retain vendor-free builds and the English default / Russian alternative README.
- See MERGE.md and MERGE.ru.md for the full comparison.

## 1.1.0 — 2026-10-03

- Command-only capabilities remain controllable and advertise no state retrieval.
- Query returns known features even when others are unknown.
- Incoming range telemetry is independent of command limits and precision.
- Different devices in an action batch execute concurrently, preserving response
  order and command order for repeated entries of the same device.
- Public HEAD availability probes return 200 without authentication.
- Form CSP permits registered HTTPS callback origins for consent redirects.
- Anonymous login GET uses stateless signed CSRF instead of allocating sessions.
- Separate login/OAuth rate limits protect valid refresh requests; trusted proxy
  CIDRs optionally enable safe X-Forwarded-For client identification.
- Basic client authentication supports raw and RFC 6749 form-encoded credentials.
- Direct TLS defaults to a public listening address when listen is omitted.
- Reconnect preserves last known state by default, with optional strict reset.
- Command confirmation requires a new update of the target feature specifically.
- Device-directory JSON files reject unknown nested structural fields and enforce
  a size limit and a single JSON value.
- Partial MQTT subscription failure affects only bound features, reports degraded
  status and retries failed filters without disabling working devices.
- Removed vendor; standard Go module download and checksum verification are used.
- English README is the default; the updated Russian guide is README.ru.md.
- Added regression tests and upstream evidence for the original audit items 12/26.

See REVIEW.ru.md for the individual findings, qualifications and test mapping.
