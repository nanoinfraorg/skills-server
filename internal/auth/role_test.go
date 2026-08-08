package auth

import "testing"

func TestDetermineRole_AdminEmailWins(t *testing.T) {
	role, ok := DetermineRole("Admin@Example.com", []string{"admin@example.com"}, []string{"submitter@example.com"})
	if !ok || role != RoleAdmin {
		t.Fatalf("role = %q, ok = %v, want admin/true", role, ok)
	}
}

func TestDetermineRole_SubmitterListRestricts(t *testing.T) {
	adminEmails := []string{"admin@example.com"}
	submitterEmails := []string{"submitter@example.com"}

	role, ok := DetermineRole("submitter@example.com", adminEmails, submitterEmails)
	if !ok || role != RoleSubmitter {
		t.Fatalf("role = %q, ok = %v, want submitter/true", role, ok)
	}

	_, ok = DetermineRole("nobody@example.com", adminEmails, submitterEmails)
	if ok {
		t.Fatalf("expected an email in neither list to be rejected when SUBMITTER_EMAILS is set")
	}
}

func TestDetermineRole_EmptySubmitterListAllowsAnyVerifiedEmail(t *testing.T) {
	adminEmails := []string{"admin@example.com"}

	role, ok := DetermineRole("anyone@example.com", adminEmails, nil)
	if !ok || role != RoleSubmitter {
		t.Fatalf("role = %q, ok = %v, want submitter/true when SUBMITTER_EMAILS is unset", role, ok)
	}
}

func TestDetermineRole_CaseInsensitive(t *testing.T) {
	role, ok := DetermineRole("  ADMIN@EXAMPLE.COM  ", []string{"admin@example.com"}, nil)
	if !ok || role != RoleAdmin {
		t.Fatalf("role = %q, ok = %v, want admin/true for a case/whitespace-different match", role, ok)
	}
}
