package o2wa

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/grokify/go-pkce"
	"golang.org/x/oauth2"
)

// csrfFormField is the form field a plain HTML form posts the CSRF token in (scripts send the X-CSRF-Token header).
const csrfFormField = "csrfToken"

// loginState travels in the OAuth2 state parameter next to the random part, so a callback whose session data is
// gone (o2wa restarted, the login was started in another browser, the callback was reloaded) still knows where
// the user was going. It is not trusted: the redirect is checked to be local, and nothing else depends on it.
type loginState struct {
	Redirect string `json:"r"`
	Retry    bool   `json:"t,omitempty"` // this login already replaces a stale one: do not start another
}

func (app *Server) oauth2Start(w http.ResponseWriter, r *http.Request, redirectURL string, retry bool) {
	random, err := randString(16)
	if err != nil {
		handleError(w, "Internal error", http.StatusInternalServerError)
		return
	}
	nonce, err := randString(16)
	if err != nil {
		handleError(w, "Internal error", http.StatusInternalServerError)
		return
	}

	codeVerifier, err := pkce.NewCodeVerifier(96)
	if err != nil {
		handleError(w, "Internal error", http.StatusInternalServerError)
		return
	}

	redirectURL = localRedirect(redirectURL)
	state := encodeState(random, loginState{Redirect: redirectURL, Retry: retry})

	flowData := oauthFlowData{State: state, Nonce: nonce, Redirect: redirectURL, CodeVerifier: codeVerifier}
	app.sessionManager.Put(r.Context(), app.oauthKey, flowData)

	codeChallenge := pkce.CodeChallengeS256(codeVerifier)

	authURL := app.config.AuthCodeURL(
		state,
		oidc.Nonce(nonce),
		oauth2.SetAuthURLParam(pkce.ParamCodeChallenge, codeChallenge),
		oauth2.SetAuthURLParam(pkce.ParamCodeChallengeMethod, pkce.MethodS256),
	)

	http.Redirect(w, r, authURL, http.StatusFound)
}

func encodeState(random string, s loginState) string {
	data, _ := json.Marshal(s) // a struct of a string and a bool always marshals
	return random + "." + base64.RawURLEncoding.EncodeToString(data)
}

func decodeState(state string) (loginState, error) {
	var s loginState
	_, encoded, ok := strings.Cut(state, ".")
	if !ok {
		return s, errors.New("state has no login data")
	}
	data, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return s, err
	}
	if err := json.Unmarshal(data, &s); err != nil {
		return s, err
	}
	s.Redirect = localRedirect(s.Redirect)
	return s, nil
}

// localRedirect returns target when it is a path on this server, "/" otherwise, so neither a crafted state nor a
// request URL can send the user to another site after the login.
func localRedirect(target string) string {
	if !strings.HasPrefix(target, "/") || strings.HasPrefix(target, "//") || strings.HasPrefix(target, "/\\") {
		return "/"
	}
	u, err := url.Parse(target)
	if err != nil || u.Scheme != "" || u.Host != "" {
		return "/"
	}
	return target
}

func (app *Server) setAuth(r *http.Request, data *authData) error {
	app.sessionManager.Put(r.Context(), app.sessionKey, *data) // a value: auth() reads one back, also within this request
	return nil
}

// auth returns the session's login, nil when the user is not logged in.
func (app *Server) auth(r *http.Request) *authData {
	data, ok := app.sessionManager.Get(r.Context(), app.sessionKey).(authData)
	if !ok {
		return nil
	}
	return &data
}

func (app *Server) csrfToken(r *http.Request) string {
	value := app.sessionManager.Get(r.Context(), app.csrfKey)
	if value != nil {
		csrfToken, ok := value.(string)
		if ok {
			return csrfToken
		}
	}

	b := make([]byte, 32)
	_, err := rand.Read(b)
	if err != nil {
		log.Fatal("Failed to generate CSRF token:", err)
	}

	csrfToken := base64.StdEncoding.EncodeToString(b)
	app.sessionManager.Put(r.Context(), app.csrfKey, csrfToken)

	return csrfToken
}

// validateCSRFToken accepts the token in the X-CSRF-Token header (fetch from the page's script) or in the
// csrfToken field of a form post (a plain form, so the browser itself handles the response, e.g. a file to open).
// The form must already be parsed.
func (app *Server) validateCSRFToken(r *http.Request) bool {
	sent := r.Header.Get("X-CSRF-Token")
	if sent == "" {
		sent = r.PostForm.Get(csrfFormField)
	}

	token, ok := app.sessionManager.Get(r.Context(), app.csrfKey).(string)
	return ok && token != "" && subtle.ConstantTimeCompare([]byte(token), []byte(sent)) == 1
}

func randString(nByte int) (string, error) {
	b := make([]byte, nByte)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func handleError(w http.ResponseWriter, err string, code int) {
	http.Error(w, err, code)
}
