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
	ctx            context.Context
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
	sessionManager.Cookie.SameSite = http.SameSiteStrictMode
	sessionManager.Cookie.Secure = true

	return &Server{
		ctx:      ctx,
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
	oauthFlowDataValue := app.sessionManager.Get(r.Context(), app.oauthKey)
	if oauthFlowDataValue == nil {
		handleError(w, "oauth flow session data not found", http.StatusBadRequest)
		return
	}

	oauthFlowData, ok := oauthFlowDataValue.(oauthFlowData)
	if !ok {
		handleError(w, "oauth flow session data invalid", http.StatusInternalServerError)
		return
	}

	if r.URL.Query().Get("state") != oauthFlowData.State {
		handleError(w, "oauth flow state did not match", http.StatusBadRequest)
		return
	}

	oauth2Token, err := app.config.Exchange(
		app.ctx,
		r.URL.Query().Get("code"),
		oauth2.SetAuthURLParam(pkce.ParamCodeVerifier, oauthFlowData.CodeVerifier),
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
	idToken, err := app.verifier.Verify(app.ctx, rawIDToken)
	if err != nil {
		handleError(w, "Failed to verify ID Token: "+err.Error(), http.StatusInternalServerError)
		return
	}

	if idToken.Nonce != oauthFlowData.Nonce {
		handleError(w, "nonce did not match", http.StatusBadRequest)
		return
	}

	app.sessionManager.Remove(r.Context(), app.oauthKey)

	var claims idTokenClaims
	if err := idToken.Claims(&claims); err != nil {
		handleError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	authData := authData{
		OAuth2Token:   *oauth2Token,
		IDTokenClaims: claims,
	}

	app.setAuth(r, &authData)
	http.Redirect(w, r, oauthFlowData.Redirect, http.StatusFound)
}
