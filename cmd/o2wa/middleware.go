package o2wa

import (
	"log"
	"net/http"
	"time"
)

func (app *Server) AuthMiddleware(requiredGroups []string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		userInfo := app.auth(r)
		if userInfo != nil && time.Now().Unix() >= userInfo.IDTokenClaims.Exp {
			// Claims are only as fresh as the ID token: renew them, or log in again.
			if err := app.refreshAuth(r, userInfo); err != nil {
				log.Printf("%s: session refresh failed, new login required: %s", userInfo.IDTokenClaims.PreferredUsername, err)
				app.sessionManager.Remove(r.Context(), app.sessionKey)
				userInfo = nil
			} else {
				userInfo = app.auth(r)
			}
		}
		if userInfo == nil {
			if r.Method != http.MethodGet {
				// A command POST comes from the page's script, which cannot follow a login redirect.
				http.Error(w, "Session expired: reload the page to log in again", http.StatusUnauthorized)
				return
			}
			app.oauth2Start(w, r, r.URL.String())
			return
		}

		if !app.requireGroups(userInfo, requiredGroups) {
			http.Error(w, "Unauthorized: insufficient group permissions", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	}
}

func (a *Server) SessionMiddleware(handler http.Handler) http.Handler {
	return a.sessionManager.LoadAndSave(handler)
}
