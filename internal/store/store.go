// Package store persists submissions, published skill versions, and scan
// reports in a single SQLite database file. It is the only package that
// touches SQL.
package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	_ "modernc.org/sqlite" // pure-Go SQLite driver, registered as "sqlite"
)

// ErrNotFound is returned when a lookup by id finds no row.
var ErrNotFound = errors.New("not found")

const schema = `
CREATE TABLE IF NOT EXISTS submissions (
	id               TEXT PRIMARY KEY,
	skill_id         TEXT NOT NULL,
	display_name     TEXT NOT NULL,
	submitter        TEXT NOT NULL,
	status           TEXT NOT NULL,
	rejection_reason TEXT,
	archive_path     TEXT NOT NULL,
	created_at       TEXT NOT NULL,
	decided_at       TEXT,
	owner            TEXT NOT NULL DEFAULT '',
	risks            TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_submissions_status ON submissions(status);
CREATE INDEX IF NOT EXISTS idx_submissions_skill_id ON submissions(skill_id);

-- skill_versions is the version history: one row per published version of
-- a skill_id, never overwritten in place.
CREATE TABLE IF NOT EXISTS skill_versions (
	id            INTEGER PRIMARY KEY AUTOINCREMENT,
	skill_id      TEXT NOT NULL,
	version       INTEGER NOT NULL,
	submission_id TEXT NOT NULL,
	display_name  TEXT NOT NULL,
	description   TEXT NOT NULL,
	github_path   TEXT NOT NULL,
	published_at  TEXT NOT NULL,
	status        TEXT NOT NULL,
	search_text   TEXT NOT NULL,
	owner         TEXT NOT NULL DEFAULT '',
	risks         TEXT NOT NULL DEFAULT '',
	UNIQUE (skill_id, version)
);
CREATE INDEX IF NOT EXISTS idx_skill_versions_skill_id ON skill_versions(skill_id);
CREATE INDEX IF NOT EXISTS idx_skill_versions_search_text ON skill_versions(search_text);

-- skills is now a thin pointer at the current version, plus the aggregate
-- download counter (which survives across versions).
CREATE TABLE IF NOT EXISTS skills (
	skill_id        TEXT PRIMARY KEY,
	current_version INTEGER NOT NULL,
	downloads       INTEGER NOT NULL DEFAULT 0,
	created_at      TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_skills_downloads ON skills(downloads);

-- scans records every run of the security scan shield (internal/scan),
-- against either a pending submission's archive or a published skill
-- version's archive. "trigger" is a SQLite keyword (used by CREATE
-- TRIGGER); it is always quoted below when referenced as a column name.
CREATE TABLE IF NOT EXISTS scans (
	id                      INTEGER PRIMARY KEY AUTOINCREMENT,
	target_type             TEXT NOT NULL,
	target_id               TEXT NOT NULL,
	"trigger"               TEXT NOT NULL,
	verdict                 TEXT NOT NULL,
	text_only_ok            INTEGER NOT NULL,
	hidden_chars_findings   TEXT NOT NULL,
	static_pattern_findings TEXT NOT NULL,
	llm_assessment          TEXT,
	scanned_at              TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_scans_target ON scans(target_type, target_id, id);

-- sessions holds authenticated Google OAuth sessions (see internal/auth
-- and internal/api's GoogleCallback/Logout). Expired rows are not
-- proactively cleaned up in v1 -- see Session's doc comment in models.go.
CREATE TABLE IF NOT EXISTS sessions (
	id         TEXT PRIMARY KEY,
	email      TEXT NOT NULL,
	role       TEXT NOT NULL,
	created_at TEXT NOT NULL,
	expires_at TEXT NOT NULL,
	csrf_token TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions(expires_at);

-- virustotal_scans records the async VirusTotal multi-engine AV sweep
-- (internal/virustotal) for a published skill version: a "pending" row is
-- inserted by a fire-and-forget upload right after a successful publish
-- (internal/api/admin.go's ApproveSubmissionCore), and later filled in by
-- the background poller once VirusTotal's analysis completes. This is a
-- brand-new table (not a column on scans) because VirusTotal's shape --
-- an analysis id, per-engine stats, a permalink -- doesn't fit scans' shape,
-- and the two are conceptually different checks (our own deterministic+LLM
-- shield vs. a third-party multi-engine AV sweep). One row per upload
-- attempt; skill_version_id is not unique since a re-published version
-- would be a different skill_versions row entirely, but is left NOT NULL
-- (never a submission id) since only a published version is ever uploaded.
CREATE TABLE IF NOT EXISTS virustotal_scans (
	id                INTEGER PRIMARY KEY AUTOINCREMENT,
	skill_version_id  INTEGER NOT NULL,
	analysis_id       TEXT NOT NULL,
	status            TEXT NOT NULL, -- "pending" | "completed" | "error"
	malicious_count   INTEGER,
	suspicious_count  INTEGER,
	harmless_count    INTEGER,
	undetected_count  INTEGER,
	permalink         TEXT,
	error_detail      TEXT,
	created_at        TEXT NOT NULL,
	checked_at        TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_virustotal_scans_skill_version ON virustotal_scans(skill_version_id, id);
CREATE INDEX IF NOT EXISTS idx_virustotal_scans_status ON virustotal_scans(status);
`

// sessionsCSRFMigration adds the csrf_token column (see Session.CSRFToken)
// to a sessions table created by a pre-web-UI version of this schema.
// schema's own "CREATE TABLE IF NOT EXISTS" only applies to a brand-new
// table, so an existing database's sessions table needs this ALTER to pick
// up the column. The error from a second run (column already exists,
// whether from a fresh database created with the column from the start, or
// a database this migration already ran against once) is deliberately
// ignored -- SQLite has no "ADD COLUMN IF NOT EXISTS".
const sessionsCSRFMigration = `ALTER TABLE sessions ADD COLUMN csrf_token TEXT NOT NULL DEFAULT '';`

// ownerRisksMigrations adds the owner and risks columns (see the Owner and
// Risks fields on Submission and SkillVersion) to submissions and
// skill_versions tables created by a pre-Skill-Card version of this schema.
// Like sessionsCSRFMigration above, schema's own "CREATE TABLE IF NOT
// EXISTS" only applies to a brand-new table, so an existing database needs
// these ALTERs to pick up the columns; the "duplicate column" error from a
// second run (this migration already applied, or a fresh database that
// already had the columns from the start) is deliberately ignored -- SQLite
// has no "ADD COLUMN IF NOT EXISTS". Both columns are optional free text
// (empty string means "not provided"), so defaulting to the empty string
// backfills every pre-existing row with the same "unset" value a brand-new
// row would get.
var ownerRisksMigrations = []string{
	`ALTER TABLE submissions ADD COLUMN owner TEXT NOT NULL DEFAULT '';`,
	`ALTER TABLE submissions ADD COLUMN risks TEXT NOT NULL DEFAULT '';`,
	`ALTER TABLE skill_versions ADD COLUMN owner TEXT NOT NULL DEFAULT '';`,
	`ALTER TABLE skill_versions ADD COLUMN risks TEXT NOT NULL DEFAULT '';`,
}

// Store wraps the SQLite database used by skills-server.
type Store struct {
	db *sql.DB
}

// Open creates the parent directory for dbPath if needed, opens (or
// creates) the SQLite database, and applies the schema. Callers must call
// Close when done.
func Open(dbPath string) (*Store, error) {
	if dir := filepath.Dir(dbPath); dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return nil, fmt.Errorf("create db directory: %w", err)
		}
	}
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, fmt.Errorf("open sqlite database: %w", err)
	}
	db.SetMaxOpenConns(1) // modernc.org/sqlite: keep writes serialized, simplest for this scale
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("apply schema: %w", err)
	}
	if _, err := db.Exec(sessionsCSRFMigration); err != nil && !strings.Contains(err.Error(), "duplicate column") {
		db.Close()
		return nil, fmt.Errorf("apply csrf_token migration: %w", err)
	}
	for _, migration := range ownerRisksMigrations {
		if _, err := db.Exec(migration); err != nil && !strings.Contains(err.Error(), "duplicate column") {
			db.Close()
			return nil, fmt.Errorf("apply owner/risks migration: %w", err)
		}
	}
	return &Store{db: db}, nil
}

// Close closes the underlying database handle.
func (s *Store) Close() error { return s.db.Close() }

// CreateSubmission inserts a new pending submission row.
func (s *Store) CreateSubmission(ctx context.Context, sub Submission) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO submissions (id, skill_id, display_name, submitter, status, rejection_reason, archive_path, created_at, decided_at, owner, risks)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		sub.ID, sub.SkillID, sub.DisplayName, sub.Submitter, string(sub.Status),
		nullableString(sub.RejectionReason), sub.ArchivePath, formatTime(sub.CreatedAt), nullableTime(sub.DecidedAt),
		sub.Owner, sub.Risks,
	)
	if err != nil {
		return fmt.Errorf("insert submission: %w", err)
	}
	return nil
}

// GetSubmission fetches one submission by id.
func (s *Store) GetSubmission(ctx context.Context, id string) (*Submission, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT id, skill_id, display_name, submitter, status, rejection_reason, archive_path, created_at, decided_at, owner, risks
		FROM submissions WHERE id = ?`, id)
	sub, err := scanSubmission(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("query submission: %w", err)
	}
	return sub, nil
}

// ListSubmissions returns submissions, optionally filtered by status
// ("pending", "approved", "rejected"); an empty status returns all of them,
// newest first.
func (s *Store) ListSubmissions(ctx context.Context, status string) ([]Submission, error) {
	query := `
		SELECT id, skill_id, display_name, submitter, status, rejection_reason, archive_path, created_at, decided_at, owner, risks
		FROM submissions`
	args := []any{}
	if status != "" {
		query += " WHERE status = ?"
		args = append(args, status)
	}
	query += " ORDER BY created_at DESC"

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("query submissions: %w", err)
	}
	defer rows.Close()

	var out []Submission
	for rows.Next() {
		sub, err := scanSubmission(rows)
		if err != nil {
			return nil, fmt.Errorf("scan submission: %w", err)
		}
		out = append(out, *sub)
	}
	return out, rows.Err()
}

// ListSubmissionsBySubmitter returns every submission created by submitter
// (matched case-insensitively, since the submitter field is a free-text
// field on a token-authenticated submission but always a lowercased,
// verified email on a session-authenticated one), newest first. Used by the
// "my submissions" page (internal/web) so a logged-in submitter can see
// their own submission history and its status.
func (s *Store) ListSubmissionsBySubmitter(ctx context.Context, submitter string) ([]Submission, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, skill_id, display_name, submitter, status, rejection_reason, archive_path, created_at, decided_at, owner, risks
		FROM submissions WHERE LOWER(submitter) = LOWER(?) ORDER BY created_at DESC`, submitter)
	if err != nil {
		return nil, fmt.Errorf("list submissions by submitter: %w", err)
	}
	defer rows.Close()

	var out []Submission
	for rows.Next() {
		sub, err := scanSubmission(rows)
		if err != nil {
			return nil, fmt.Errorf("scan submission: %w", err)
		}
		out = append(out, *sub)
	}
	return out, rows.Err()
}

// DecideSubmission records the approve/reject outcome for a submission.
func (s *Store) DecideSubmission(ctx context.Context, id string, status SubmissionStatus, reason *string, decidedAt time.Time) error {
	res, err := s.db.ExecContext(ctx, `
		UPDATE submissions SET status = ?, rejection_reason = ?, decided_at = ? WHERE id = ?`,
		string(status), nullableString(reason), formatTime(decidedAt), id,
	)
	if err != nil {
		return fmt.Errorf("update submission: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// MaxVersion returns the highest published version number for skillID, or 0
// if it has never been published. The next publish should use
// MaxVersion+1.
func (s *Store) MaxVersion(ctx context.Context, skillID string) (int64, error) {
	var version sql.NullInt64
	err := s.db.QueryRowContext(ctx, `SELECT MAX(version) FROM skill_versions WHERE skill_id = ?`, skillID).Scan(&version)
	if err != nil {
		return 0, fmt.Errorf("query max skill version: %w", err)
	}
	if !version.Valid {
		return 0, nil
	}
	return version.Int64, nil
}

// CreateSkillVersion inserts a new, immutable skill_versions row and returns
// its generated id (used as the scans.target_id when a scan is attached to
// this version).
func (s *Store) CreateSkillVersion(ctx context.Context, sv SkillVersion) (int64, error) {
	searchText := strings.ToLower(sv.SkillID + " " + sv.DisplayName + " " + sv.Description)
	res, err := s.db.ExecContext(ctx, `
		INSERT INTO skill_versions (skill_id, version, submission_id, display_name, description, github_path, published_at, status, search_text, owner, risks)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		sv.SkillID, sv.Version, sv.SubmissionID, sv.DisplayName, sv.Description, sv.GitHubPath,
		formatTime(sv.PublishedAt), string(sv.Status), searchText, sv.Owner, sv.Risks,
	)
	if err != nil {
		return 0, fmt.Errorf("insert skill version: %w", err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		return 0, fmt.Errorf("get skill version id: %w", err)
	}
	return id, nil
}

// GetSkillVersion fetches one specific version of skillID.
func (s *Store) GetSkillVersion(ctx context.Context, skillID string, version int64) (*SkillVersion, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT id, skill_id, version, submission_id, display_name, description, github_path, published_at, status, owner, risks
		FROM skill_versions WHERE skill_id = ? AND version = ?`, skillID, version)
	sv, err := scanSkillVersion(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("query skill version: %w", err)
	}
	return sv, nil
}

// GetSkillVersionByID fetches a skill_versions row by its own internal
// auto-increment id (as opposed to GetSkillVersion's skill_id+version
// lookup) -- used by internal/virustotal's poller, which only has the
// skill_version_id a virustotal_scans row points at and needs the actual
// skill_id/version pair to call SetSkillVersionStatus.
func (s *Store) GetSkillVersionByID(ctx context.Context, id int64) (*SkillVersion, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT id, skill_id, version, submission_id, display_name, description, github_path, published_at, status, owner, risks
		FROM skill_versions WHERE id = ?`, id)
	sv, err := scanSkillVersion(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("query skill version by id: %w", err)
	}
	return sv, nil
}

// ListSkillVersions returns every version of skillID, newest first.
func (s *Store) ListSkillVersions(ctx context.Context, skillID string) ([]SkillVersion, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, skill_id, version, submission_id, display_name, description, github_path, published_at, status, owner, risks
		FROM skill_versions WHERE skill_id = ? ORDER BY version DESC`, skillID)
	if err != nil {
		return nil, fmt.Errorf("list skill versions: %w", err)
	}
	defer rows.Close()

	var out []SkillVersion
	for rows.Next() {
		sv, err := scanSkillVersion(rows)
		if err != nil {
			return nil, fmt.Errorf("scan skill version: %w", err)
		}
		out = append(out, *sv)
	}
	return out, rows.Err()
}

// SetSkillVersionStatus flips one version's status (used to quarantine a
// version the scan shield later blocked, via a manual rescan or the daily
// scheduler).
func (s *Store) SetSkillVersionStatus(ctx context.Context, skillID string, version int64, status SkillVersionStatus) error {
	res, err := s.db.ExecContext(ctx, `
		UPDATE skill_versions SET status = ? WHERE skill_id = ? AND version = ?`,
		string(status), skillID, version,
	)
	if err != nil {
		return fmt.Errorf("update skill version status: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// SetSkillPointer creates the thin skills pointer row on first publish, or
// repoints an existing one at a newly published version. downloads and
// created_at are left untouched on an update (created_at is only set on the
// initial insert).
func (s *Store) SetSkillPointer(ctx context.Context, skillID string, version int64, now time.Time) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO skills (skill_id, current_version, downloads, created_at)
		VALUES (?, ?, 0, ?)
		ON CONFLICT(skill_id) DO UPDATE SET current_version = excluded.current_version`,
		skillID, version, formatTime(now),
	)
	if err != nil {
		return fmt.Errorf("set skill pointer: %w", err)
	}
	return nil
}

// GetSkill fetches the thin current-version pointer row for skillID.
func (s *Store) GetSkill(ctx context.Context, skillID string) (*Skill, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT skill_id, current_version, downloads, created_at FROM skills WHERE skill_id = ?`, skillID)
	var sk Skill
	var createdAt string
	if err := row.Scan(&sk.SkillID, &sk.CurrentVersion, &sk.Downloads, &createdAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("query skill: %w", err)
	}
	created, err := parseTime(createdAt)
	if err != nil {
		return nil, err
	}
	sk.CreatedAt = created
	return &sk, nil
}

// skillDetailColumns is shared by every query that joins skills to its
// current skill_versions row.
const skillDetailColumns = `
		s.skill_id, sv.display_name, sv.description, sv.version, sv.submission_id,
		sv.github_path, sv.published_at, sv.status, s.downloads, s.created_at, sv.owner, sv.risks`

const skillDetailFrom = `
		FROM skills s
		JOIN skill_versions sv ON sv.skill_id = s.skill_id AND sv.version = s.current_version`

// GetSkillDetail fetches skillID's current version, denormalized with its
// thin pointer row. Unlike SearchSkills/TrendingSkills, this does not
// exclude a quarantined current version -- callers (the public detail
// endpoint) show it, clearly marked via Status, rather than hiding it.
func (s *Store) GetSkillDetail(ctx context.Context, skillID string) (*SkillDetail, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT`+skillDetailColumns+skillDetailFrom+`
		WHERE s.skill_id = ?`, skillID)
	sd, err := scanSkillDetail(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("query skill detail: %w", err)
	}
	return sd, nil
}

// SearchSkills returns published skills (excluding any whose current
// version is quarantined) whose denormalized current-version search text
// contains the (lowercased) query as a substring, case-insensitively.
func (s *Store) SearchSkills(ctx context.Context, query string, limit int) ([]SkillDetail, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT`+skillDetailColumns+skillDetailFrom+`
		WHERE sv.status != ? AND sv.search_text LIKE ?
		ORDER BY s.downloads DESC, sv.published_at DESC LIMIT ?`,
		string(SkillVersionQuarantined), "%"+strings.ToLower(query)+"%", limit,
	)
	if err != nil {
		return nil, fmt.Errorf("search skills: %w", err)
	}
	defer rows.Close()
	return scanSkillDetails(rows)
}

// TrendingSkills returns published skills (excluding any whose current
// version is quarantined) ordered by downloads descending.
func (s *Store) TrendingSkills(ctx context.Context, limit int) ([]SkillDetail, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT`+skillDetailColumns+skillDetailFrom+`
		WHERE sv.status != ?
		ORDER BY s.downloads DESC, sv.published_at DESC LIMIT ?`,
		string(SkillVersionQuarantined), limit,
	)
	if err != nil {
		return nil, fmt.Errorf("trending skills: %w", err)
	}
	defer rows.Close()
	return scanSkillDetails(rows)
}

// ListActiveSkillDetails returns every skill's current version, excluding
// any already-quarantined ones, for the daily re-scan scheduler (which has
// no reason to re-scan something an admin already had to pull).
func (s *Store) ListActiveSkillDetails(ctx context.Context) ([]SkillDetail, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT`+skillDetailColumns+skillDetailFrom+`
		WHERE sv.status != ?
		ORDER BY s.skill_id ASC`,
		string(SkillVersionQuarantined),
	)
	if err != nil {
		return nil, fmt.Errorf("list active skill details: %w", err)
	}
	defer rows.Close()
	return scanSkillDetails(rows)
}

// ListAllSkillDetails returns every published skill's current version,
// quarantined or not, newest-created skill_id last. Unlike
// ListActiveSkillDetails (used by the daily rescan scheduler, which has no
// reason to rescan something already quarantined), the admin dashboard
// (internal/web) needs to show every skill so an admin can see which ones
// are currently quarantined and rescan any of them, quarantined or not.
func (s *Store) ListAllSkillDetails(ctx context.Context) ([]SkillDetail, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT`+skillDetailColumns+skillDetailFrom+`
		ORDER BY s.skill_id ASC`,
	)
	if err != nil {
		return nil, fmt.Errorf("list all skill details: %w", err)
	}
	defer rows.Close()
	return scanSkillDetails(rows)
}

// IncrementDownloads bumps a published skill's aggregate download counter
// by one, regardless of which version is current.
func (s *Store) IncrementDownloads(ctx context.Context, skillID string) error {
	res, err := s.db.ExecContext(ctx, `UPDATE skills SET downloads = downloads + 1 WHERE skill_id = ?`, skillID)
	if err != nil {
		return fmt.Errorf("increment downloads: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// CreateScan inserts one scan report row and returns its generated id.
func (s *Store) CreateScan(ctx context.Context, sc Scan) (int64, error) {
	res, err := s.db.ExecContext(ctx, `
		INSERT INTO scans (target_type, target_id, "trigger", verdict, text_only_ok, hidden_chars_findings, static_pattern_findings, llm_assessment, scanned_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		string(sc.TargetType), sc.TargetID, string(sc.Trigger), string(sc.Verdict), boolToInt(sc.TextOnlyOK),
		sc.HiddenCharsFindingsJSON, sc.StaticPatternFindingsJSON, nullableString(sc.LLMAssessmentJSON), formatTime(sc.ScannedAt),
	)
	if err != nil {
		return 0, fmt.Errorf("insert scan: %w", err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		return 0, fmt.Errorf("get scan id: %w", err)
	}
	return id, nil
}

// GetLatestScan returns the most recently recorded scan for the given
// target (a submission id, or a skill_versions row id formatted as a
// string), or ErrNotFound if none has run yet.
func (s *Store) GetLatestScan(ctx context.Context, targetType ScanTargetType, targetID string) (*Scan, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT id, target_type, target_id, "trigger", verdict, text_only_ok, hidden_chars_findings, static_pattern_findings, llm_assessment, scanned_at
		FROM scans WHERE target_type = ? AND target_id = ? ORDER BY id DESC LIMIT 1`,
		string(targetType), targetID,
	)
	sc, err := scanScanRow(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("query latest scan: %w", err)
	}
	return sc, nil
}

// CreateVirusTotalScan inserts a new "pending" VirusTotal scan row for
// skillVersionID and returns its generated id. Called by the fire-and-forget
// upload goroutine right after a successful upload (see
// internal/virustotal.UploadAndRecord) -- never called at all if the upload
// itself failed, so there is no "upload failed" row shape to represent.
func (s *Store) CreateVirusTotalScan(ctx context.Context, skillVersionID int64, analysisID string, createdAt time.Time) (int64, error) {
	res, err := s.db.ExecContext(ctx, `
		INSERT INTO virustotal_scans (skill_version_id, analysis_id, status, created_at, checked_at)
		VALUES (?, ?, ?, ?, ?)`,
		skillVersionID, analysisID, string(VirusTotalScanPending), formatTime(createdAt), formatTime(createdAt),
	)
	if err != nil {
		return 0, fmt.Errorf("insert virustotal scan: %w", err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		return 0, fmt.Errorf("get virustotal scan id: %w", err)
	}
	return id, nil
}

// GetLatestVirusTotalScan returns the most recently recorded VirusTotal scan
// for skillVersionID, or ErrNotFound if none was ever uploaded -- either
// VirusTotal isn't configured, or the fire-and-forget upload itself failed
// (which never creates a row at all; see UploadAndRecord).
func (s *Store) GetLatestVirusTotalScan(ctx context.Context, skillVersionID int64) (*VirusTotalScan, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT id, skill_version_id, analysis_id, status, malicious_count, suspicious_count, harmless_count, undetected_count, permalink, error_detail, created_at, checked_at
		FROM virustotal_scans WHERE skill_version_id = ? ORDER BY id DESC LIMIT 1`,
		skillVersionID,
	)
	vt, err := scanVirusTotalScan(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("query latest virustotal scan: %w", err)
	}
	return vt, nil
}

// ListPendingVirusTotalScans returns every VirusTotal scan row still
// awaiting a result, oldest first, for the background poller to check on.
func (s *Store) ListPendingVirusTotalScans(ctx context.Context) ([]VirusTotalScan, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, skill_version_id, analysis_id, status, malicious_count, suspicious_count, harmless_count, undetected_count, permalink, error_detail, created_at, checked_at
		FROM virustotal_scans WHERE status = ? ORDER BY id ASC`,
		string(VirusTotalScanPending),
	)
	if err != nil {
		return nil, fmt.Errorf("list pending virustotal scans: %w", err)
	}
	defer rows.Close()

	var out []VirusTotalScan
	for rows.Next() {
		vt, err := scanVirusTotalScan(rows)
		if err != nil {
			return nil, fmt.Errorf("scan virustotal scan: %w", err)
		}
		out = append(out, *vt)
	}
	return out, rows.Err()
}

// UpdateVirusTotalScanResult records a completed VirusTotal analysis's
// per-engine stats and permalink against an existing row, flipping its
// status to "completed".
func (s *Store) UpdateVirusTotalScanResult(ctx context.Context, id, malicious, suspicious, harmless, undetected int64, permalink string, checkedAt time.Time) error {
	res, err := s.db.ExecContext(ctx, `
		UPDATE virustotal_scans
		SET status = ?, malicious_count = ?, suspicious_count = ?, harmless_count = ?, undetected_count = ?, permalink = ?, checked_at = ?
		WHERE id = ?`,
		string(VirusTotalScanCompleted), malicious, suspicious, harmless, undetected, permalink, formatTime(checkedAt), id,
	)
	if err != nil {
		return fmt.Errorf("update virustotal scan result: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// MarkVirusTotalScanError flips a row's status to "error" with detail,
// recording that VirusTotal returned a definitive but unexpectedly-shaped
// response for this analysis (see internal/virustotal.ErrMalformedAnalysis)
// -- a permanent failure the poller should stop retrying, unlike a
// transient network/rate-limit error, which just leaves the row "pending".
func (s *Store) MarkVirusTotalScanError(ctx context.Context, id int64, detail string, checkedAt time.Time) error {
	res, err := s.db.ExecContext(ctx, `
		UPDATE virustotal_scans SET status = ?, error_detail = ?, checked_at = ? WHERE id = ?`,
		string(VirusTotalScanError), detail, formatTime(checkedAt), id,
	)
	if err != nil {
		return fmt.Errorf("mark virustotal scan error: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// CreateSession inserts a new authenticated-session row.
func (s *Store) CreateSession(ctx context.Context, sess Session) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO sessions (id, email, role, created_at, expires_at, csrf_token)
		VALUES (?, ?, ?, ?, ?, ?)`,
		sess.ID, sess.Email, string(sess.Role), formatTime(sess.CreatedAt), formatTime(sess.ExpiresAt), sess.CSRFToken,
	)
	if err != nil {
		return fmt.Errorf("insert session: %w", err)
	}
	return nil
}

// GetSession fetches a session by id, returning ErrNotFound both when no
// such row exists and when it exists but has already passed its
// expires_at -- a lazy "treat expired as not-found" check, sufficient for
// v1 since there's no separate cleanup job (see Session's doc comment).
func (s *Store) GetSession(ctx context.Context, id string) (*Session, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT id, email, role, created_at, expires_at, csrf_token FROM sessions WHERE id = ?`, id)
	var sess Session
	var role, createdAt, expiresAt string
	if err := row.Scan(&sess.ID, &sess.Email, &role, &createdAt, &expiresAt, &sess.CSRFToken); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("query session: %w", err)
	}
	sess.Role = SessionRole(role)
	created, err := parseTime(createdAt)
	if err != nil {
		return nil, err
	}
	sess.CreatedAt = created
	expires, err := parseTime(expiresAt)
	if err != nil {
		return nil, err
	}
	sess.ExpiresAt = expires
	if !time.Now().Before(sess.ExpiresAt) {
		return nil, ErrNotFound
	}
	return &sess, nil
}

// DeleteSession removes a session row by id (used by logout). Deleting an
// id that doesn't exist is not an error -- logout always succeeds.
func (s *Store) DeleteSession(ctx context.Context, id string) error {
	if _, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE id = ?`, id); err != nil {
		return fmt.Errorf("delete session: %w", err)
	}
	return nil
}

type rowScanner interface {
	Scan(dest ...any) error
}

func scanSubmission(row rowScanner) (*Submission, error) {
	var sub Submission
	var status string
	var rejectionReason, decidedAt sql.NullString
	var createdAt string
	if err := row.Scan(
		&sub.ID, &sub.SkillID, &sub.DisplayName, &sub.Submitter, &status,
		&rejectionReason, &sub.ArchivePath, &createdAt, &decidedAt, &sub.Owner, &sub.Risks,
	); err != nil {
		return nil, err
	}
	sub.Status = SubmissionStatus(status)
	if rejectionReason.Valid {
		sub.RejectionReason = &rejectionReason.String
	}
	created, err := parseTime(createdAt)
	if err != nil {
		return nil, err
	}
	sub.CreatedAt = created
	if decidedAt.Valid {
		t, err := parseTime(decidedAt.String)
		if err != nil {
			return nil, err
		}
		sub.DecidedAt = &t
	}
	return &sub, nil
}

func scanSkillVersion(row rowScanner) (*SkillVersion, error) {
	var sv SkillVersion
	var publishedAt, status string
	if err := row.Scan(
		&sv.ID, &sv.SkillID, &sv.Version, &sv.SubmissionID, &sv.DisplayName, &sv.Description,
		&sv.GitHubPath, &publishedAt, &status, &sv.Owner, &sv.Risks,
	); err != nil {
		return nil, err
	}
	published, err := parseTime(publishedAt)
	if err != nil {
		return nil, err
	}
	sv.PublishedAt = published
	sv.Status = SkillVersionStatus(status)
	return &sv, nil
}

func scanSkillDetail(row rowScanner) (*SkillDetail, error) {
	var sd SkillDetail
	var publishedAt, createdAt, status string
	if err := row.Scan(
		&sd.SkillID, &sd.DisplayName, &sd.Description, &sd.Version, &sd.SubmissionID,
		&sd.GitHubPath, &publishedAt, &status, &sd.Downloads, &createdAt, &sd.Owner, &sd.Risks,
	); err != nil {
		return nil, err
	}
	published, err := parseTime(publishedAt)
	if err != nil {
		return nil, err
	}
	sd.PublishedAt = published
	sd.Status = SkillVersionStatus(status)
	created, err := parseTime(createdAt)
	if err != nil {
		return nil, err
	}
	sd.CreatedAt = created
	return &sd, nil
}

func scanSkillDetails(rows *sql.Rows) ([]SkillDetail, error) {
	var out []SkillDetail
	for rows.Next() {
		sd, err := scanSkillDetail(rows)
		if err != nil {
			return nil, fmt.Errorf("scan skill detail: %w", err)
		}
		out = append(out, *sd)
	}
	return out, rows.Err()
}

func scanScanRow(row rowScanner) (*Scan, error) {
	var sc Scan
	var targetType, trigger, verdict, scannedAt string
	var textOnlyOK int64
	var llmAssessment sql.NullString
	if err := row.Scan(
		&sc.ID, &targetType, &sc.TargetID, &trigger, &verdict, &textOnlyOK,
		&sc.HiddenCharsFindingsJSON, &sc.StaticPatternFindingsJSON, &llmAssessment, &scannedAt,
	); err != nil {
		return nil, err
	}
	sc.TargetType = ScanTargetType(targetType)
	sc.Trigger = ScanTrigger(trigger)
	sc.Verdict = ScanVerdict(verdict)
	sc.TextOnlyOK = textOnlyOK != 0
	if llmAssessment.Valid {
		sc.LLMAssessmentJSON = &llmAssessment.String
	}
	scanned, err := parseTime(scannedAt)
	if err != nil {
		return nil, err
	}
	sc.ScannedAt = scanned
	return &sc, nil
}

func scanVirusTotalScan(row rowScanner) (*VirusTotalScan, error) {
	var vt VirusTotalScan
	var status, createdAt, checkedAt string
	var malicious, suspicious, harmless, undetected sql.NullInt64
	var permalink, errorDetail sql.NullString
	if err := row.Scan(
		&vt.ID, &vt.SkillVersionID, &vt.AnalysisID, &status,
		&malicious, &suspicious, &harmless, &undetected,
		&permalink, &errorDetail, &createdAt, &checkedAt,
	); err != nil {
		return nil, err
	}
	vt.Status = VirusTotalScanStatus(status)
	if malicious.Valid {
		vt.MaliciousCount = &malicious.Int64
	}
	if suspicious.Valid {
		vt.SuspiciousCount = &suspicious.Int64
	}
	if harmless.Valid {
		vt.HarmlessCount = &harmless.Int64
	}
	if undetected.Valid {
		vt.UndetectedCount = &undetected.Int64
	}
	if permalink.Valid {
		vt.Permalink = &permalink.String
	}
	if errorDetail.Valid {
		vt.ErrorDetail = &errorDetail.String
	}
	created, err := parseTime(createdAt)
	if err != nil {
		return nil, err
	}
	vt.CreatedAt = created
	checked, err := parseTime(checkedAt)
	if err != nil {
		return nil, err
	}
	vt.CheckedAt = checked
	return &vt, nil
}

func formatTime(t time.Time) string { return t.UTC().Format(time.RFC3339Nano) }

func parseTime(s string) (time.Time, error) { return time.Parse(time.RFC3339Nano, s) }

func nullableString(s *string) any {
	if s == nil {
		return nil
	}
	return *s
}

func nullableTime(t *time.Time) any {
	if t == nil {
		return nil
	}
	return formatTime(*t)
}

func boolToInt(b bool) int64 {
	if b {
		return 1
	}
	return 0
}
