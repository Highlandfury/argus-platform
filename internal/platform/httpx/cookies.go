package httpx

import (
	"net/http"
	"time"
)

// Cookie and header names for the session + CSRF pair (SPEC §24.3).
const (
	SessionCookieName = "argus_session"
	CSRFCookieName    = "argus_csrf"
	CSRFHeaderName    = "X-CSRF-Token"
)

// issueCookie is the single cookie-writing path (HttpOnly/SameSite always set;
// Secure is enabled in production via cfg — hence the targeted gosec waiver).
func issueCookie(w http.ResponseWriter, name, value string, httpOnly, secure bool, expires time.Time) {
	http.SetCookie(w, &http.Cookie{ //nolint:gosec // Secure is configuration-driven (prod=on); HttpOnly/SameSite always set
		Name:     name,
		Value:    value,
		Path:     "/",
		HttpOnly: httpOnly,
		SameSite: http.SameSiteLaxMode,
		Secure:   secure,
		Expires:  expires,
	})
}

// SetSessionCookies issues the session cookie (HttpOnly) and the CSRF cookie
// (readable by the UI for the double-submit header).
func SetSessionCookies(w http.ResponseWriter, sessionRaw, csrfRaw string, expires time.Time, secure bool) {
	issueCookie(w, SessionCookieName, sessionRaw, true, secure, expires)
	issueCookie(w, CSRFCookieName, csrfRaw, false, secure, expires)
}

// ClearSessionCookies expires both cookies (logout).
func ClearSessionCookies(w http.ResponseWriter, secure bool) {
	expired := time.Unix(0, 0)
	issueCookie(w, SessionCookieName, "", true, secure, expired)
	issueCookie(w, CSRFCookieName, "", false, secure, expired)
}

// SessionCookie returns the raw session token ("" when absent).
func SessionCookie(r *http.Request) string {
	c, err := r.Cookie(SessionCookieName)
	if err != nil {
		return ""
	}
	return c.Value
}

// CSRFCookie returns the raw CSRF token ("" when absent).
func CSRFCookie(r *http.Request) string {
	c, err := r.Cookie(CSRFCookieName)
	if err != nil {
		return ""
	}
	return c.Value
}
