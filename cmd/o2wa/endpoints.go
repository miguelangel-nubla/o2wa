package o2wa

import (
	"encoding/json"
	"net/http"
)

func (app *Server) EndpointValues(w http.ResponseWriter, r *http.Request) {
	userInfo := app.templateVariables(w, r)

	// Serialize to JSON
	userInfoJSON, err := json.Marshal(userInfo)
	if err != nil {
		http.Error(w, "Failed to serialize user info to JSON", http.StatusInternalServerError)
		return
	}

	// Set the content type and write the JSON response
	noStore(w) // holds the CSRF token
	w.Header().Set("Content-Type", "application/json")
	w.Write(userInfoJSON)
}

// EndpointLogout ends this application's session.
func (app *Server) EndpointLogout(w http.ResponseWriter, r *http.Request) {
	// Clear the session cookie
	err := app.sessionManager.Destroy(r.Context())
	if err != nil {
		http.Error(w, "Could not end session", http.StatusInternalServerError)
		return
	}

	// No redirect to a page: it would start a new login, which the provider's own session completes silently.
	noStore(w)
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Write([]byte("Logged out of this application. The identity provider's session is not ended here.\n"))
}
