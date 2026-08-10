package virustotal

import (
	"bytes"
	"context"
	"log/slog"
	"time"

	"github.com/nanoinfraorg/skills-server/internal/store"
)

// UploadAndRecord uploads archive (named filename) to VirusTotal via client
// and, on success, records a new "pending" virustotal_scans row against
// skillVersionID via st.
//
// Callers run this in their own goroutine (see
// internal/api/admin.go's ApproveSubmissionCore, which calls it with
// context.Background() right after a successful publish) so that
// VirusTotal's upload latency -- or a full VirusTotal outage -- never adds
// to the approve request's response time and never fails or rolls back the
// publish. On an upload error (network, rate limit, invalid key), it logs a
// warning and returns without creating a row at all: the Security Audits
// panel then simply shows no VirusTotal entry for that skill, identical to
// VirusTotal not being configured. There is deliberately no "upload failed"
// pseudo-status -- see the virustotal_scans schema's doc comment in
// internal/store/store.go.
func UploadAndRecord(ctx context.Context, client Client, st *store.Store, logger *slog.Logger, now func() time.Time, skillVersionID int64, archive []byte, filename string) {
	analysisID, err := client.Upload(ctx, bytes.NewReader(archive), filename)
	if err != nil {
		logger.Warn("virustotal: upload failed, skipping this skill version's audit entry", "error", err, "skill_version_id", skillVersionID)
		return
	}

	if _, err := st.CreateVirusTotalScan(ctx, skillVersionID, analysisID, now()); err != nil {
		logger.Error("virustotal: uploaded but could not record the pending scan", "error", err, "skill_version_id", skillVersionID, "analysis_id", analysisID)
		return
	}

	logger.Info("virustotal: uploaded for analysis", "skill_version_id", skillVersionID, "analysis_id", analysisID)
}
