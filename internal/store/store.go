// Package store persists submissions and published skills in a single
// SQLite database file. It is the only package that touches SQL.
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
	decided_at       TEXT
);
CREATE INDEX IF NOT EXISTS idx_submissions_status ON submissions(status);
CREATE INDEX IF NOT EXISTS idx_submissions_skill_id ON submissions(skill_id);

CREATE TABLE IF NOT EXISTS skills (
	skill_id     TEXT PRIMARY KEY,
	display_name TEXT NOT NULL,
	description  TEXT NOT NULL,
	version      INTEGER NOT NULL,
	submitter    TEXT NOT NULL,
	published_at TEXT NOT NULL,
	github_path  TEXT NOT NULL,
	downloads    INTEGER NOT NULL DEFAULT 0,
	search_text  TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_skills_search_text ON skills(search_text);
CREATE INDEX IF NOT EXISTS idx_skills_downloads ON skills(downloads);
`

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
	return &Store{db: db}, nil
}

// Close closes the underlying database handle.
func (s *Store) Close() error { return s.db.Close() }

// CreateSubmission inserts a new pending submission row.
func (s *Store) CreateSubmission(ctx context.Context, sub Submission) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO submissions (id, skill_id, display_name, submitter, status, rejection_reason, archive_path, created_at, decided_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		sub.ID, sub.SkillID, sub.DisplayName, sub.Submitter, string(sub.Status),
		nullableString(sub.RejectionReason), sub.ArchivePath, formatTime(sub.CreatedAt), nullableTime(sub.DecidedAt),
	)
	if err != nil {
		return fmt.Errorf("insert submission: %w", err)
	}
	return nil
}

// GetSubmission fetches one submission by id.
func (s *Store) GetSubmission(ctx context.Context, id string) (*Submission, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT id, skill_id, display_name, submitter, status, rejection_reason, archive_path, created_at, decided_at
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
		SELECT id, skill_id, display_name, submitter, status, rejection_reason, archive_path, created_at, decided_at
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

// NextVersion returns the version number the next publish of skillID should
// use: 1 if the skill has never been published, or the current published
// version + 1 otherwise.
func (s *Store) NextVersion(ctx context.Context, skillID string) (int64, error) {
	var version int64
	err := s.db.QueryRowContext(ctx, `SELECT version FROM skills WHERE skill_id = ?`, skillID).Scan(&version)
	if errors.Is(err, sql.ErrNoRows) {
		return 1, nil
	}
	if err != nil {
		return 0, fmt.Errorf("query skill version: %w", err)
	}
	return version + 1, nil
}

// UpsertSkill inserts a newly published skill or overwrites the row for a
// republished skill_id.
func (s *Store) UpsertSkill(ctx context.Context, sk Skill) error {
	searchText := strings.ToLower(sk.SkillID + " " + sk.DisplayName + " " + sk.Description)
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO skills (skill_id, display_name, description, version, submitter, published_at, github_path, downloads, search_text)
		VALUES (?, ?, ?, ?, ?, ?, ?, 0, ?)
		ON CONFLICT(skill_id) DO UPDATE SET
			display_name = excluded.display_name,
			description = excluded.description,
			version = excluded.version,
			submitter = excluded.submitter,
			published_at = excluded.published_at,
			github_path = excluded.github_path,
			search_text = excluded.search_text`,
		sk.SkillID, sk.DisplayName, sk.Description, sk.Version, sk.Submitter,
		formatTime(sk.PublishedAt), sk.GitHubPath, searchText,
	)
	if err != nil {
		return fmt.Errorf("upsert skill: %w", err)
	}
	return nil
}

// GetSkill fetches one published skill by id.
func (s *Store) GetSkill(ctx context.Context, skillID string) (*Skill, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT skill_id, display_name, description, version, submitter, published_at, github_path, downloads
		FROM skills WHERE skill_id = ?`, skillID)
	sk, err := scanSkill(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("query skill: %w", err)
	}
	return sk, nil
}

// SearchSkills returns published skills whose denormalized search text
// contains the (lowercased) query as a substring, case-insensitively.
func (s *Store) SearchSkills(ctx context.Context, query string, limit int) ([]Skill, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT skill_id, display_name, description, version, submitter, published_at, github_path, downloads
		FROM skills WHERE search_text LIKE ? ORDER BY downloads DESC, published_at DESC LIMIT ?`,
		"%"+strings.ToLower(query)+"%", limit,
	)
	if err != nil {
		return nil, fmt.Errorf("search skills: %w", err)
	}
	defer rows.Close()
	return scanSkills(rows)
}

// TrendingSkills returns published skills ordered by downloads descending.
func (s *Store) TrendingSkills(ctx context.Context, limit int) ([]Skill, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT skill_id, display_name, description, version, submitter, published_at, github_path, downloads
		FROM skills ORDER BY downloads DESC, published_at DESC LIMIT ?`, limit,
	)
	if err != nil {
		return nil, fmt.Errorf("trending skills: %w", err)
	}
	defer rows.Close()
	return scanSkills(rows)
}

// IncrementDownloads bumps a published skill's download counter by one.
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
		&rejectionReason, &sub.ArchivePath, &createdAt, &decidedAt,
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

func scanSkill(row rowScanner) (*Skill, error) {
	var sk Skill
	var publishedAt string
	if err := row.Scan(
		&sk.SkillID, &sk.DisplayName, &sk.Description, &sk.Version, &sk.Submitter,
		&publishedAt, &sk.GitHubPath, &sk.Downloads,
	); err != nil {
		return nil, err
	}
	published, err := parseTime(publishedAt)
	if err != nil {
		return nil, err
	}
	sk.PublishedAt = published
	return &sk, nil
}

func scanSkills(rows *sql.Rows) ([]Skill, error) {
	var out []Skill
	for rows.Next() {
		sk, err := scanSkill(rows)
		if err != nil {
			return nil, fmt.Errorf("scan skill: %w", err)
		}
		out = append(out, *sk)
	}
	return out, rows.Err()
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
