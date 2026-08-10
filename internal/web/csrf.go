package web

import (
	"crypto/subtle"
	"net/http"

	"github.com/nanoinfraorg/skills-server/internal/store"
)

// CSRF protection.
//
// Every JSON API request is authenticated either by a custom header
// (X-Submitter-Token / X-Admin-Token, which a cross-site request cannot
// set) or, when session-cookie-authenticated, is safe simply because the
// JSON API has no HTML forms pointed at it. Neither protection applies
// here: an HTML <form> POST relies on the browser sending the session
// cookie automatically, including on a cross-site form submission, so
// every state-changing form below (submit, admin approve/reject/rescan)
// must prove it was actually rendered by this server for this session, not
// forged by a third-party page the victim merely visited while logged in.
//
// Mechanism chosen: a per-session token, generated once at login
// (alongside the session id itself, in internal/api's GoogleCallback) and
// stored on the session row (store.Session.CSRFToken). Every protected
// form embeds it as a hidden csrf_token field; every protected POST
// handler calls validCSRF, which compares the submitted field against the
// current session's own token in constant time. This was picked over a
// signed double-submit cookie because sessions already persist server-side
// in SQLite -- validation is just the same store.GetSession lookup the
// handler already performed to authenticate/authorize the request in the
// first place, with no second cookie to mint, sign, or verify.
//
// A request that has a valid session cookie but supplies no csrf_token, or
// the wrong one, is rejected before the underlying action (approve,
// reject, rescan, create-submission) runs -- forging the cookie alone is
// not enough, since the attacker cannot read the token out of a
// cross-origin page it never actually loaded.
func validCSRF(r *http.Request, sess *store.Session) bool {
	if sess == nil || sess.CSRFToken == "" {
		return false
	}
	token := r.FormValue("csrf_token")
	if token == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(token), []byte(sess.CSRFToken)) == 1
}
