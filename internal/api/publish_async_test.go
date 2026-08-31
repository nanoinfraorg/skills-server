package api

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/nanoinfraorg/skills-server/internal/store"
)

// seedPendingSubmission posts a real submission through the API, so the row and
// its archive are the ones production would have.
func seedPendingSubmission(t *testing.T, h *Handler, skillID string) string {
	t.Helper()
	mux := NewMux(h)
	archive := buildZip(t, map[string]string{"SKILL.md": skillMDNamed(skillID)})
	req := submissionRequest(t, "submitter-secret", map[string]string{
		"skill_id":     skillID,
		"display_name": skillID,
		"submitter":    "alice",
	}, archive)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("seed submission: status=%d body=%s", rec.Code, rec.Body.String())
	}
	return decodeJSON[map[string]string](t, rec.Body)["id"]
}

func skillMDNamed(skillID string) string {
	return "---\nname: " + skillID +
		"\ndescription: A seeded skill for a test. Use when testing.\n---\n\n# " + skillID + "\n"
}

// latestScanID is the id of the most recent scan recorded for this submission, or
// 0 when none exists. Comparing it before and after an approval says whether a
// second scan ran without needing a list query the store does not have.
func latestScanID(t *testing.T, h *Handler, submissionID string) int64 {
	t.Helper()
	sc, err := h.Store.GetLatestScan(context.Background(), store.ScanTargetSubmission, submissionID)
	if errors.Is(err, store.ErrNotFound) {
		return 0
	}
	if err != nil {
		t.Fatalf("get latest scan: %v", err)
	}
	return sc.ID
}

// triggerScan runs the scan the admin dashboard's own button runs.
func triggerScan(t *testing.T, h *Handler, submissionID string) {
	t.Helper()
	mux := NewMux(h)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/scan/"+submissionID, nil)
	req.Header.Set("X-Admin-Token", "admin-secret")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("trigger scan: status=%d body=%s", rec.Code, rec.Body.String())
	}
}

// The approve button used to hold the request open for an LLM classification
// with a 30-second client timeout followed by a GitHub round trip. Approving ten
// submissions meant watching that ten times, which is what these pin.

func TestApproveReturnsBeforeTheWorkFinishes(t *testing.T) {
	h, pub := testHandler(t)
	var publishes sync.WaitGroup
	h.TrackBackgroundPublishes(&publishes)
	ctx := context.Background()
	id := seedPendingSubmission(t, h, "approve-me")

	started, subErr := h.ApproveSubmissionAsync(ctx, id)

	if subErr != nil {
		t.Fatalf("approve: %+v", subErr)
	}
	if !started {
		t.Fatal("expected the approval to be claimed")
	}
	// Claimed, and the caller is already free.
	sub, err := h.Store.GetSubmission(ctx, id)
	if err != nil {
		t.Fatalf("get submission: %v", err)
	}
	if sub.Status != store.StatusPublishing && sub.Status != store.StatusApproved {
		t.Fatalf("status = %s, want publishing or already approved", sub.Status)
	}

	publishes.Wait()
	if len(pub.calls) != 1 {
		t.Fatalf("expected the publish to happen in the background, got %d calls", len(pub.calls))
	}
	sub, err = h.Store.GetSubmission(ctx, id)
	if err != nil {
		t.Fatalf("get submission after publish: %v", err)
	}
	if sub.Status != store.StatusApproved {
		t.Fatalf("status after publish = %s, want approved", sub.Status)
	}
}

func TestASecondApproveIsRefusedRatherThanPublishingTwice(t *testing.T) {
	// The claim is a conditional UPDATE from `pending`, so it is the lock as
	// well as the status: two clicks on the same row produce one publish.
	h, _ := testHandler(t)
	var publishes sync.WaitGroup
	h.TrackBackgroundPublishes(&publishes)
	ctx := context.Background()
	id := seedPendingSubmission(t, h, "approve-once")

	if _, subErr := h.ApproveSubmissionAsync(ctx, id); subErr != nil {
		t.Fatalf("first approve: %+v", subErr)
	}
	_, subErr := h.ApproveSubmissionAsync(ctx, id)

	if subErr == nil {
		t.Fatal("expected the second approve to be refused")
	}
	if subErr.Status != 409 {
		t.Fatalf("status = %d, want 409", subErr.Status)
	}
	publishes.Wait()
}

func TestTheClaimIsAtomicUnderConcurrency(t *testing.T) {
	h, pub := testHandler(t)
	var publishes sync.WaitGroup
	h.TrackBackgroundPublishes(&publishes)
	ctx := context.Background()
	id := seedPendingSubmission(t, h, "approve-race")

	var wg sync.WaitGroup
	claims := make([]bool, 8)
	for i := range claims {
		wg.Add(1)
		go func(slot int) {
			defer wg.Done()
			started, _ := h.ApproveSubmissionAsync(ctx, id)
			claims[slot] = started
		}(i)
	}
	wg.Wait()
	publishes.Wait()

	won := 0
	for _, claimed := range claims {
		if claimed {
			won++
		}
	}
	if won != 1 {
		t.Fatalf("expected exactly one claim to win, got %d", won)
	}
	if len(pub.calls) != 1 {
		t.Fatalf("expected one publish, got %d", len(pub.calls))
	}
}

func TestAScanAlreadyRecordedIsNotRunAgain(t *testing.T) {
	// A submission's archive is written once and never modified, so a scan
	// already recorded against it describes these exact bytes -- and its verdict
	// is what the admin reads in the dashboard immediately before clicking
	// approve. Re-running it paid for a second LLM call that told nobody
	// anything.
	h, _ := testHandler(t)
	ctx := context.Background()
	id := seedPendingSubmission(t, h, "scan-once")

	triggerScan(t, h, id)
	before := latestScanID(t, h, id)

	outcome, subErr := h.ApproveSubmissionCore(ctx, id)

	if subErr != nil {
		t.Fatalf("approve: %+v", subErr)
	}
	if !outcome.Published {
		t.Fatalf("expected a publish, got %q", outcome.Reason)
	}
	if after := latestScanID(t, h, id); after != before {
		t.Fatalf("a second scan ran (%d -> %d); the recorded one should have been reused", before, after)
	}
}

func TestWithNoRecordedScanTheApprovalStillRunsOne(t *testing.T) {
	// "Nothing publishes unscanned" has to hold whether or not somebody pressed
	// the scan button first.
	h, _ := testHandler(t)
	ctx := context.Background()
	id := seedPendingSubmission(t, h, "scan-none")

	if _, subErr := h.ApproveSubmissionCore(ctx, id); subErr != nil {
		t.Fatalf("approve: %+v", subErr)
	}

	if latestScanID(t, h, id) == 0 {
		t.Fatal("expected the approval to record a scan of its own")
	}
}

func TestReconcileReturnsAStuckSubmissionToPending(t *testing.T) {
	// A crash between the claim and the outcome leaves a row nobody is working
	// on. Nothing was published, so it goes back to pending.
	h, _ := testHandler(t)
	ctx := context.Background()
	id := seedPendingSubmission(t, h, "stuck")
	claimed, err := h.Store.ClaimSubmissionForPublish(ctx, id)
	if err != nil || !claimed {
		t.Fatalf("claim: %v %v", claimed, err)
	}

	h.ReconcilePublishing(ctx)

	sub, err := h.Store.GetSubmission(ctx, id)
	if err != nil {
		t.Fatalf("get submission: %v", err)
	}
	if sub.Status != store.StatusPending {
		t.Fatalf("status = %s, want pending", sub.Status)
	}
}

func TestReconcileApprovesASubmissionThatFinishedBeforeTheRestart(t *testing.T) {
	// The version row is the commit point: if one exists, the publish finished
	// and only the status write was lost.
	h, _ := testHandler(t)
	ctx := context.Background()
	id := seedPendingSubmission(t, h, "finished")
	if _, subErr := h.ApproveSubmissionCore(ctx, id); subErr != nil {
		t.Fatalf("approve: %+v", subErr)
	}
	claimed, err := h.Store.ClaimSubmissionForPublish(ctx, id)
	if err != nil {
		t.Fatalf("claim: %v", err)
	}
	if claimed {
		t.Fatal("an approved submission should not be claimable")
	}
	// Put it back into the state a crash would have left.
	if err := h.Store.DecideSubmission(ctx, id, store.StatusPublishing, nil, h.now()); err != nil {
		t.Fatalf("force publishing: %v", err)
	}

	h.ReconcilePublishing(ctx)

	sub, err := h.Store.GetSubmission(ctx, id)
	if err != nil {
		t.Fatalf("get submission: %v", err)
	}
	if sub.Status != store.StatusApproved {
		t.Fatalf("status = %s, want approved", sub.Status)
	}
}
