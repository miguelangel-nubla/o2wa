package o2wa

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"golang.org/x/oauth2"
)

// startLogin requests /cmd without a login and returns the provider URL o2wa redirects to.
func startLogin(t *testing.T, client *http.Client, base string) *url.URL {
	t.Helper()
	resp, err := client.Get(base + "/cmd?x=1")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	loc, err := resp.Location()
	if resp.StatusCode != http.StatusFound || err != nil {
		t.Fatalf("GET /cmd without a login: got %d, want a login redirect", resp.StatusCode)
	}
	return loc
}

func get(t *testing.T, client *http.Client, u string) (*http.Response, string) {
	t.Helper()
	resp, err := client.Get(u)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var b strings.Builder
	buf := make([]byte, 4096)
	for {
		n, err := resp.Body.Read(buf)
		b.Write(buf[:n])
		if err != nil {
			break
		}
	}
	return resp, b.String()
}

func sessionCookie(client *http.Client, base string) string {
	u, _ := url.Parse(base)
	for _, c := range client.Jar.Cookies(u) {
		if c.Name == "session" {
			return c.Value
		}
	}
	return ""
}

func callback(base string, state string, extra ...string) string {
	q := url.Values{"state": {state}}
	for i := 0; i+1 < len(extra); i += 2 {
		q.Set(extra[i], extra[i+1])
	}
	return base + "/callback?" + q.Encode()
}

func TestLoginFlow(t *testing.T) {
	f := newFakeIssuer(t)
	f.groups = []string{"admins"}
	app := NewServer("client", "secret", f.srv.URL, "https://app/callback")
	srv, client := serve(t, app, nil)

	auth := startLogin(t, client, srv.URL)
	f.nonce = auth.Query().Get("nonce")
	before := sessionCookie(client, srv.URL)

	resp, _ := get(t, client, callback(srv.URL, auth.Query().Get("state"), "code", "code-1"))
	if resp.StatusCode != http.StatusFound || resp.Header.Get("Location") != "/cmd?x=1" {
		t.Fatalf("callback: got %d %q, want a redirect to /cmd?x=1", resp.StatusCode, resp.Header.Get("Location"))
	}
	if after := sessionCookie(client, srv.URL); after == "" || after == before {
		t.Errorf("session token not renewed at login (before %q, after %q)", before, after)
	}
	if _, body := get(t, client, srv.URL+"/cmd"); body != "ran" {
		t.Errorf("after the login: got %q, want ran", body)
	}

	// Reloading the used callback (back button, bookmark) takes a logged-in user to the page.
	resp, _ = get(t, client, callback(srv.URL, auth.Query().Get("state"), "code", "code-1"))
	if resp.StatusCode != http.StatusFound || resp.Header.Get("Location") != "/cmd?x=1" {
		t.Errorf("reloaded callback: got %d %q, want a redirect to /cmd?x=1", resp.StatusCode, resp.Header.Get("Location"))
	}
}

func TestStaleCallbackStartsOneNewLogin(t *testing.T) {
	f := newFakeIssuer(t)
	app := NewServer("client", "secret", f.srv.URL, "https://app/callback")
	srv, client := serve(t, app, nil)
	state := startLogin(t, client, srv.URL).Query().Get("state")

	// Another browser (or o2wa after a restart) has no session data for this login: one new login, same target.
	_, other := serve(t, app, nil)
	resp, _ := get(t, other, callback(srv.URL, state, "code", "code-1"))
	loc, _ := resp.Location()
	if resp.StatusCode != http.StatusFound || loc == nil || !strings.HasPrefix(loc.String(), f.srv.URL+"/auth") {
		t.Fatalf("stale callback: got %d %v, want a new login", resp.StatusCode, loc)
	}
	retry, err := decodeState(loc.Query().Get("state"))
	if err != nil || !retry.Retry || retry.Redirect != "/cmd?x=1" {
		t.Fatalf("new login state %+v (%v): want a retry to /cmd?x=1", retry, err)
	}

	// That one goes stale as well: the cookie does not stick, so stop instead of looping.
	_, third := serve(t, app, nil)
	resp, body := get(t, third, callback(srv.URL, loc.Query().Get("state"), "code", "code-1"))
	if resp.StatusCode != http.StatusBadRequest || !strings.Contains(body, "open /cmd?x=1 again") {
		t.Errorf("second stale callback: got %d %q, want 400 asking to open the page again", resp.StatusCode, body)
	}

	// A state that is not o2wa's: no login data to go on.
	resp, _ = get(t, third, callback(srv.URL, "garbage"))
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("unknown state: got %d, want 400", resp.StatusCode)
	}
}

func TestStaleCallbackWhenLoggedIn(t *testing.T) {
	f := newFakeIssuer(t)
	app := NewServer("client", "secret", f.srv.URL, "https://app/callback")
	srv, client := serve(t, app, &authData{
		OAuth2Token:   oauth2.Token{AccessToken: "a", Expiry: time.Now().Add(time.Hour)},
		IDTokenClaims: idTokenClaims{Sub: "user-1", Exp: time.Now().Add(time.Hour).Unix(), Groups: []string{"admins"}},
	})
	resp, _ := get(t, client, callback(srv.URL, encodeState("x", loginState{Redirect: "/cmd"})))
	if resp.StatusCode != http.StatusFound || resp.Header.Get("Location") != "/cmd" {
		t.Errorf("got %d %q, want a redirect to /cmd", resp.StatusCode, resp.Header.Get("Location"))
	}
}

func TestLoginRefusedByProvider(t *testing.T) {
	f := newFakeIssuer(t)
	app := NewServer("client", "secret", f.srv.URL, "https://app/callback")
	srv, client := serve(t, app, nil)
	state := startLogin(t, client, srv.URL).Query().Get("state")
	resp, body := get(t, client, callback(srv.URL, state, "error", "access_denied", "error_description", "not allowed"))
	if resp.StatusCode != http.StatusForbidden || !strings.Contains(body, "access_denied: not allowed") {
		t.Errorf("got %d %q, want 403 with the provider's error", resp.StatusCode, body)
	}
}

func TestRedirectsStayLocal(t *testing.T) {
	for target, want := range map[string]string{
		"/wifi/faro?x=1":       "/wifi/faro?x=1",
		"":                     "/",
		"//evil.example/x":     "/",
		"/\\evil.example":      "/",
		"https://evil.example": "/",
		"evil":                 "/",
	} {
		if got := localRedirect(target); got != want {
			t.Errorf("localRedirect(%q) = %q, want %q", target, got, want)
		}
		if s, err := decodeState(encodeState("r", loginState{Redirect: target})); err != nil || s.Redirect != want {
			t.Errorf("state with %q: got %q (%v), want %q", target, s.Redirect, err, want)
		}
	}
}
