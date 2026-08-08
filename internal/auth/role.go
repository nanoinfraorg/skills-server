package auth

import "strings"

// Role is the privilege level assigned to a Google-authenticated session,
// computed once at login time (DetermineRole) and stored on the session
// row rather than re-derived on every request -- so a later ADMIN_EMAILS /
// SUBMITTER_EMAILS change takes effect on the next login, not
// retroactively against sessions that already exist, mirroring how
// rotating ADMIN_TOKEN today doesn't invalidate requests already using the
// old value until it's rejected on their next attempt.
type Role string

const (
	RoleAdmin     Role = "admin"
	RoleSubmitter Role = "submitter"
)

// DetermineRole computes the Role a just-verified Google account email
// should receive, given the ADMIN_EMAILS and SUBMITTER_EMAILS allowlists
// (both expected pre-normalized: lowercased and trimmed, as
// internal/config.Load produces them). ok is false if email qualifies for
// neither role, meaning the caller must reject the login.
//
// SUBMITTER_EMAILS is intentionally allowed to be empty, in which case
// *any* Google account with a verified email qualifies for RoleSubmitter.
// This is deliberately permissive: a submission created this way only
// ever reaches "pending" -- it never publishes, scans, or otherwise
// mutates the public catalog by itself, since an admin still has to
// review and approve it through the existing pipeline. Opening up
// "propose a submission" to any real, Google-verified human is judged an
// acceptable default; operators who want a closed submitter list can set
// SUBMITTER_EMAILS to restrict it, same as ADMIN_EMAILS.
func DetermineRole(email string, adminEmails, submitterEmails []string) (Role, bool) {
	email = normalizeEmail(email)
	if containsEmail(adminEmails, email) {
		return RoleAdmin, true
	}
	if len(submitterEmails) == 0 || containsEmail(submitterEmails, email) {
		return RoleSubmitter, true
	}
	return "", false
}

func normalizeEmail(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
}

func containsEmail(list []string, email string) bool {
	for _, e := range list {
		if normalizeEmail(e) == email {
			return true
		}
	}
	return false
}
