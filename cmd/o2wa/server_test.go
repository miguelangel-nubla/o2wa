package o2wa

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v3"
	"github.com/go-jose/go-jose/v3/jwt"
	"golang.org/x/oauth2"
)

// fakeIssuer is a minimal OIDC provider: discovery, JWKS and a refresh_token grant that issues an ID token for
// `sub` with `groups`.
type fakeIssuer struct {
	srv    *httptest.Server
	key    *rsa.PrivateKey
	sub    string
	groups []string
}

func newFakeIssuer(t *testing.T) *fakeIssuer {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeIssuer{key: key, sub: "user-1"}
	mux := http.NewServeMux()
	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"issuer": f.srv.URL, "authorization_endpoint": f.srv.URL + "/auth", "token_endpoint": f.srv.URL + "/token",
			"jwks_uri": f.srv.URL + "/jwks", "id_token_signing_alg_values_supported": []string{"RS256"},
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &key.PublicKey, KeyID: "k", Algorithm: "RS256", Use: "sig"}}})
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		if r.FormValue("grant_type") != "refresh_token" || r.FormValue("refresh_token") != "refresh-1" {
			http.Error(w, `{"error":"invalid_grant"}`, http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"access_token": "access-2", "token_type": "Bearer", "expires_in": 300, "refresh_token": "refresh-2",
			"id_token": f.idToken(t, time.Now().Add(5*time.Minute)),
		})
	})
	return f
}

func (f *fakeIssuer) idToken(t *testing.T, exp time.Time) string {
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: f.key}, (&jose.SignerOptions{}).WithHeader("kid", "k"))
	if err != nil {
		t.Fatal(err)
	}
	claims := map[string]any{"iss": f.srv.URL, "sub": f.sub, "aud": "client", "exp": exp.Unix(), "iat": time.Now().Unix(),
		"preferred_username": "user", "groups": f.groups}
	raw, err := jwt.Signed(signer).Claims(claims).CompactSerialize()
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// serve runs app behind its session middleware, with /seed putting `data` in the session (nil: no session).
func serve(t *testing.T, app *Server, data *authData) (*httptest.Server, *http.Client) {
	mux := http.NewServeMux()
	mux.HandleFunc("/seed", func(w http.ResponseWriter, r *http.Request) {
		if data != nil {
			app.setAuth(r, data)
		}
	})
	mux.HandleFunc("/cmd", app.AuthMiddleware([]string{"admins"}, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ran"))
	}))
	srv := httptest.NewTLSServer(app.SessionMiddleware(mux)) // the session cookie is Secure
	t.Cleanup(srv.Close)
	client := srv.Client()
	client.Jar, _ = cookiejar.New(nil)
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	if _, err := client.Get(srv.URL + "/seed"); err != nil {
		t.Fatal(err)
	}
	return srv, client
}

func expiredSession(refresh string, groups ...string) *authData {
	return &authData{
		OAuth2Token:   oauth2.Token{AccessToken: "access-1", RefreshToken: refresh, Expiry: time.Now().Add(-time.Minute)},
		IDTokenClaims: idTokenClaims{Sub: "user-1", PreferredUsername: "user", Exp: time.Now().Add(-time.Minute).Unix(), Groups: groups},
	}
}

func post(t *testing.T, client *http.Client, url string) (int, string) {
	resp, err := client.Post(url, "application/json", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var b strings.Builder
	buf := make([]byte, 512)
	n, _ := resp.Body.Read(buf)
	b.Write(buf[:n])
	return resp.StatusCode, b.String()
}

func TestExpiredClaimsAreRefreshed(t *testing.T) {
	f := newFakeIssuer(t)
	app := NewServer("client", "secret", f.srv.URL, "https://app/callback")

	f.groups = []string{"admins"}
	srv, client := serve(t, app, expiredSession("refresh-1"))
	if code, body := post(t, client, srv.URL+"/cmd"); code != 200 || body != "ran" {
		t.Fatalf("refresh keeping the group: got %d %q", code, body)
	}

	// The provider dropped the user from the group: the next expiry must enforce it.
	f.groups = nil
	srv, client = serve(t, app, expiredSession("refresh-1", "admins"))
	if code, _ := post(t, client, srv.URL+"/cmd"); code != http.StatusUnauthorized {
		t.Fatalf("group removed at the provider: got %d, want 401", code)
	}
}

func TestRefreshFailureEndsSession(t *testing.T) {
	f := newFakeIssuer(t)
	app := NewServer("client", "secret", f.srv.URL, "https://app/callback")
	f.groups = []string{"admins"}

	for name, data := range map[string]*authData{
		"no refresh token": expiredSession("", "admins"),
		"refresh refused":  expiredSession("revoked", "admins"),
	} {
		srv, client := serve(t, app, data)
		if code, body := post(t, client, srv.URL+"/cmd"); code != http.StatusUnauthorized || !strings.Contains(body, "Session expired") {
			t.Errorf("%s: POST got %d %q, want 401 session expired", name, code, body)
		}
		resp, err := client.Get(srv.URL + "/cmd")
		if err != nil {
			t.Fatal(err)
		}
		if resp.StatusCode != http.StatusFound || !strings.HasPrefix(resp.Header.Get("Location"), f.srv.URL+"/auth") {
			t.Errorf("%s: GET got %d %s, want a login redirect", name, resp.StatusCode, resp.Header.Get("Location"))
		}
	}

	f.sub = "someone-else"
	srv, client := serve(t, app, expiredSession("refresh-1", "admins"))
	if code, _ := post(t, client, srv.URL+"/cmd"); code != http.StatusUnauthorized {
		t.Errorf("ID token for another subject: got %d, want 401", code)
	}
}

func TestEachLoginHasItsOwnPKCEVerifier(t *testing.T) {
	f := newFakeIssuer(t)
	app := NewServer("client", "secret", f.srv.URL, "https://app/callback")
	challenge := func() string {
		srv, client := serve(t, app, nil)
		resp, err := client.Get(srv.URL + "/cmd")
		if err != nil {
			t.Fatal(err)
		}
		loc, _ := resp.Location()
		return loc.Query().Get("code_challenge")
	}
	if a, b := challenge(), challenge(); a == "" || a == b {
		t.Fatalf("code challenges %q and %q: want two different ones", a, b)
	}
}
