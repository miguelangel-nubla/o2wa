package o2wa

import (
	"context"
	"encoding/gob"
	"errors"
	"log"
	"net/http"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/grokify/go-pkce"
	"golang.org/x/oauth2"

	"github.com/alexedwards/scs/v2"
)

type idTokenClaims struct {
	Iss               string   `json:"iss"`
	Sub               string   `json:"sub"`
	Aud               string   `json:"aud"`
	Exp               int64    `json:"exp"`
	Nbf               int64    `json:"nbf"`
	Iat               int64    `json:"iat"`
	Nonce             string   `json:"nonce"`
	Azp               string   `json:"azp"`
	Name              string   `json:"name"`
	PreferredUsername string   `json:"preferred_username"`
	Scopes            []string `json:"scopes"`
	Groups            []string `json:"groups"`
}

type authData struct {
	OAuth2Token   oauth2.Token
	IDTokenClaims idTokenClaims
}

type oauthFlowData struct {
	State        string
	Nonce        string
	Redirect     string
	CodeVerifier string // PKCE verifier of this login only
}

type Server struct {
	config         oauth2.Config
	verifier       *oidc.IDTokenVerifier
	sessionManager *scs.SessionManager
	sessionKey     string
	oauthKey       string
	csrfKey        string
}

func init() {
	gob.Register(authData{})
	gob.Register(oauthFlowData{})
}

func NewServer(clientID, clientSecret, oidcIssuer, callbackURL string) *Server {
	ctx := context.Background()

	provider := discoverProvider(ctx, oidcIssuer)

	oidcConfig := &oidc.Config{ClientID: clientID}
	verifier := provider.Verifier(oidcConfig)

	sessionManager := scs.New()
	sessionManager.Lifetime = 24 * time.Hour
	sessionManager.Cookie.Persist = true
	// Strict: a link from another site arrives without the session, so it cannot open, logged in, a page whose
	// script runs its command on load. The cost: the identity provider must be on the same site as o2wa, or its
	// redirect back to the callback comes without the cookie and the login cannot finish.
	sessionManager.Cookie.SameSite = http.SameSiteStrictMode
	sessionManager.Cookie.Secure = true

	return &Server{
		verifier: verifier,
		config: oauth2.Config{
			ClientID:     clientID,
			ClientSecret: clientSecret,
			Endpoint:     provider.Endpoint(),
			RedirectURL:  callbackURL,
			Scopes:       []string{oidc.ScopeOpenID, "profile", "groups"},
		},
		sessionManager: sessionManager,
		sessionKey:     "authData",
		oauthKey:       "oauthFlowData",
		csrfKey:        "csrfToken",
	}
}

// discoverProvider retries OIDC discovery until the issuer answers, so o2wa waits for an identity provider that
// starts after it (at boot, for example) instead of exiting.
func discoverProvider(ctx context.Context, issuer string) *oidc.Provider {
	delay := time.Second
	for {
		provider, err := oidc.NewProvider(ctx, issuer)
		if err == nil {
			return provider
		}
		log.Printf("OIDC discovery failed, retrying in %s: %s", delay, err)
		time.Sleep(delay)
		if delay < 30*time.Second {
			delay *= 2
		}
	}
}

// refreshAuth renews the session's tokens with the refresh token and re-reads the claims (groups included) from
// the new ID token, so a group removal or an expired account takes effect when the ID token expires, not when
// the session does. It fails when the provider gave no refresh token, refuses it, or returns no valid ID token for
// the same subject: the caller then starts a new login.
func (app *Server) refreshAuth(r *http.Request, data *authData) error {
	if data.OAuth2Token.RefreshToken == "" {
		return errors.New("no refresh token")
	}
	expired := data.OAuth2Token
	expired.Expiry = time.Unix(1, 0) // force the token source to refresh
	token, err := app.config.TokenSource(r.Context(), &expired).Token()
	if err != nil {
		return err
	}
	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		return errors.New("refresh returned no ID token")
	}
	idToken, err := app.verifier.Verify(r.Context(), rawIDToken)
	if err != nil {
		return err
	}
	var claims idTokenClaims
	if err := idToken.Claims(&claims); err != nil {
		return err
	}
	if claims.Sub != data.IDTokenClaims.Sub {
		return errors.New("refreshed ID token is for another subject")
	}
	return app.setAuth(r, &authData{OAuth2Token: *token, IDTokenClaims: claims})
}

func (app *Server) Oauth2Callback(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()

	flow, ok := app.sessionManager.Get(r.Context(), app.oauthKey).(oauthFlowData)
	if !ok || query.Get("state") != flow.State {
		app.staleCallback(w, r)
		return
	}

	if e := query.Get("error"); e != "" {
		// The provider refused the login (access denied, consent declined...): nothing to exchange.
		app.sessionManager.Remove(r.Context(), app.oauthKey)
		msg := "Login failed: " + e
		if d := query.Get("error_description"); d != "" {
			msg += ": " + d
		}
		handleError(w, msg, http.StatusForbidden)
		return
	}

	oauth2Token, err := app.config.Exchange(
		r.Context(),
		query.Get("code"),
		oauth2.SetAuthURLParam(pkce.ParamCodeVerifier, flow.CodeVerifier),
	)
	if err != nil {
		handleError(w, "Failed to exchange token: "+err.Error(), http.StatusInternalServerError)
		return
	}

	rawIDToken, ok := oauth2Token.Extra("id_token").(string)
	if !ok {
		handleError(w, "Token response has no ID token", http.StatusInternalServerError)
		return
	}
	idToken, err := app.verifier.Verify(r.Context(), rawIDToken)
	if err != nil {
		handleError(w, "Failed to verify ID Token: "+err.Error(), http.StatusInternalServerError)
		return
	}

	if idToken.Nonce != flow.Nonce {
		handleError(w, "nonce did not match", http.StatusBadRequest)
		return
	}

	var claims idTokenClaims
	if err := idToken.Claims(&claims); err != nil {
		handleError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	app.sessionManager.Remove(r.Context(), app.oauthKey)
	// A new session token for the logged-in session: a token planted or seen before the login is worth nothing.
	if err := app.sessionManager.RenewToken(r.Context()); err != nil {
		handleError(w, "Internal error", http.StatusInternalServerError)
		return
	}
	app.setAuth(r, &authData{OAuth2Token: *oauth2Token, IDTokenClaims: claims})
	http.Redirect(w, r, localRedirect(flow.Redirect), http.StatusFound)
}

// staleCallback handles a callback that does not belong to the login this session has in progress: o2wa restarted
// (sessions live in memory), the login was started in another browser or app, it was replaced by a newer login in
// another tab, or the callback URL was reloaded or bookmarked. Instead of failing, take the user where they were
// going: directly when already logged in, through one new login otherwise. A second stale callback in a row means
// the session cookie does not stick (blocked cookies, another browser each time), and another login would loop.
func (app *Server) staleCallback(w http.ResponseWriter, r *http.Request) {
	state, err := decodeState(r.URL.Query().Get("state"))
	if err != nil {
		state = loginState{Redirect: "/"}
	}
	if app.auth(r) != nil {
		http.Redirect(w, r, state.Redirect, http.StatusFound)
		return
	}
	if err != nil || state.Retry {
		handleError(w, "Login expired or started in another browser: open "+state.Redirect+" again to log in",
			http.StatusBadRequest)
		return
	}
	log.Printf("login callback without its session data, starting a new login for %s", state.Redirect)
	app.oauth2Start(w, r, state.Redirect, true)
}
