package bridge

import (
	"bytes"
	"html"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
)

func consentRequest(t *testing.T, s *Server, approved bool) (*httptest.ResponseRecorder, *http.Request) {
	t.Helper()
	w := httptest.NewRecorder()
	_, _, err := s.newSession(w, "1")
	if err != nil {
		t.Fatal(err)
	}
	cookie := w.Result().Cookies()[0]
	q := url.Values{"client_id": {"yandex-client"}, "redirect_uri": {"https://social.yandex.net/broker/redirect"}, "response_type": {"code"}, "state": {`private-state-<script>alert(1)</script>`}}
	r := httptest.NewRequest("GET", "/dialog/authorize?"+q.Encode(), nil)
	r.AddCookie(cookie)
	w = httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if s.Config.Clients[0].Trusted {
		return w, nil
	}
	tx := regexp.MustCompile(`name="transaction_id" value="([^"]+)"`).FindStringSubmatch(w.Body.String())
	csrf := regexp.MustCompile(`name="csrf" value="([^"]+)"`).FindStringSubmatch(w.Body.String())
	if len(tx) != 2 || len(csrf) != 2 {
		t.Fatal("consent form missing")
	}
	decision := "no"
	if approved {
		decision = "yes"
	}
	form := url.Values{"transaction_id": {tx[1]}, "csrf": {csrf[1]}, "approve": {decision}}
	r = httptest.NewRequest("POST", "/dialog/authorize/decision", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.AddCookie(cookie)
	w = httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	// Rebuild the request so replay tests don't depend on an already read body.
	replay := httptest.NewRequest("POST", r.URL.String(), strings.NewReader(form.Encode()))
	replay.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	replay.AddCookie(cookie)
	return w, replay
}

func TestOAuthConsentReturnDocument(t *testing.T) {
	for _, tc := range []struct {
		name              string
		approved, trusted bool
	}{{"approved", true, false}, {"denied", false, false}, {"trusted", true, true}} {
		t.Run(tc.name, func(t *testing.T) {
			s, _, _ := fixture(t)
			s.Config.Clients[0].Trusted = tc.trusted
			w, replay := consentRequest(t, s, tc.approved)
			if w.Code != 200 || w.Header().Get("Location") != "" || w.Header().Get("Cache-Control") != "no-store" {
				t.Fatal("OAuth return must finish with a non-cached document", w.Code)
			}
			body := w.Body.String()
			if !strings.Contains(body, `http-equiv="refresh"`) || strings.Contains(body, "<script>") || strings.Contains(body, "<form") {
				t.Fatal("unsafe or missing return navigation")
			}
			links := regexp.MustCompile(`href="([^"]+)"`).FindStringSubmatch(body)
			meta := regexp.MustCompile(`content="0;url=([^"]+)"`).FindStringSubmatch(body)
			if len(links) != 2 || len(meta) != 2 || html.UnescapeString(links[1]) != html.UnescapeString(meta[1]) {
				t.Fatal("automatic navigation and fallback disagree")
			}
			u, err := url.Parse(html.UnescapeString(links[1]))
			if err != nil || u.Scheme != "https" || u.Host != "social.yandex.net" || u.Path != "/broker/redirect" {
				t.Fatal("unexpected callback")
			}
			if u.Query().Get("state") != `private-state-<script>alert(1)</script>` || u.Query().Get("client_id") != "yandex-client" {
				t.Fatal("callback values changed")
			}
			if tc.approved {
				if u.Query().Get("code") == "" || u.Query().Get("error") != "" || len(s.codes) != 1 {
					t.Fatal("authorization code missing")
				}
			} else if u.Query().Get("error") != "access_denied" || len(s.codes) != 0 {
				t.Fatal("denial created a code")
			}
			if replay != nil {
				w = httptest.NewRecorder()
				s.Handler().ServeHTTP(w, replay)
				if w.Code != http.StatusBadRequest {
					t.Fatal("consent replay accepted")
				}
			}
		})
	}
}

func TestOAuthLogsStatusWithoutSecrets(t *testing.T) {
	s, _, _ := fixture(t)
	var logs bytes.Buffer
	s.Log = slog.New(slog.NewJSONHandler(&logs, nil))
	w, replay := consentRequest(t, s, true)
	link := regexp.MustCompile(`href="([^"]+)"`).FindStringSubmatch(w.Body.String())
	if len(link) != 2 {
		t.Fatal("callback missing")
	}
	u, _ := url.Parse(html.UnescapeString(link[1]))
	w = httptest.NewRecorder()
	s.Handler().ServeHTTP(w, replay)
	q := url.Values{"client_id": {"untrusted-private-client"}, "redirect_uri": {"https://example.org/private"}, "state": {"private-query-state"}}
	request(t, s, "GET", "/dialog/authorize?"+q.Encode(), "", "")
	log := logs.String()
	for _, required := range []string{`"msg":"OAuth request"`, `"path":"/dialog/authorize/decision"`, `"status":200`, `"status":400`, `"reason":"expired_or_reused_transaction"`, `"reason":"unknown_client"`} {
		if !strings.Contains(log, required) {
			t.Fatal("missing safe diagnostic", required)
		}
	}
	for _, secret := range []string{u.Query().Get("code"), "private-state", "private-query-state", "untrusted-private-client", "client-secret", replay.FormValue("csrf"), replay.FormValue("transaction_id")} {
		if secret != "" && strings.Contains(log, secret) {
			t.Fatal("secret in OAuth logs")
		}
	}
}
