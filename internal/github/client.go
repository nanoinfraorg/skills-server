// Package github implements just enough of the GitHub REST API — via plain
// net/http, no SDK dependency — to publish a skill's files into the private
// nanoinfraorg/skills repository using the Contents API.
package github

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// DefaultBaseURL is the production GitHub REST API endpoint. Tests override
// this via WithBaseURL to point at an httptest server.
const DefaultBaseURL = "https://api.github.com"

// File is one file to write into the target repository.
type File struct {
	// Path is relative to the skill's directory, e.g. "SKILL.md" or
	// "scripts/run.py". It must not contain ".." or start with "/"; callers
	// are expected to pass already-validated pipeline.Entry names.
	Path string
	// Content is the raw (not base64-encoded) file content.
	Content []byte
}

// Client publishes files to a single GitHub repository via the Contents API.
type Client struct {
	httpClient *http.Client
	token      string
	repo       string // "owner/name"
	baseURL    string
}

// Option configures a Client.
type Option func(*Client)

// WithBaseURL overrides the GitHub API base URL, for tests.
func WithBaseURL(url string) Option {
	return func(c *Client) { c.baseURL = url }
}

// WithHTTPClient overrides the underlying http.Client, for tests.
func WithHTTPClient(hc *http.Client) Option {
	return func(c *Client) { c.httpClient = hc }
}

// New creates a Client for the given "owner/name" repo, authenticated with a
// personal access token that has repo scope.
func New(token, repo string, opts ...Option) *Client {
	c := &Client{
		httpClient: &http.Client{Timeout: 30 * time.Second},
		token:      token,
		repo:       repo,
		baseURL:    DefaultBaseURL,
	}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

// contentsResponse is the subset of the Contents API's GET response this
// client needs: the blob sha, required to update an existing file.
type contentsResponse struct {
	SHA string `json:"sha"`
}

// PublishFiles writes every file under "<skillID>/<file.Path>" on the
// repository's default branch (main), creating or updating each one as
// needed, and returns an error on the first failure. Each file is committed
// individually via the Contents API (fine at the small, single-skill-archive
// scale this server targets; see the README for why the Git Trees API
// wasn't used).
func (c *Client) PublishFiles(ctx context.Context, skillID string, files []File, commitMessage string) error {
	for _, f := range files {
		repoPath := skillID + "/" + f.Path
		sha, err := c.currentSHA(ctx, repoPath)
		if err != nil {
			return fmt.Errorf("look up existing sha for %s: %w", repoPath, err)
		}
		if err := c.putFile(ctx, repoPath, f.Content, commitMessage, sha); err != nil {
			return fmt.Errorf("publish %s: %w", repoPath, err)
		}
	}
	return nil
}

// currentSHA returns the blob sha of an existing file at repoPath, or "" if
// the file does not exist yet (a 404 is not an error here).
func (c *Client) currentSHA(ctx context.Context, repoPath string) (string, error) {
	url := fmt.Sprintf("%s/repos/%s/contents/%s", c.baseURL, c.repo, repoPath)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	c.setHeaders(req)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
		var body contentsResponse
		if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
			return "", fmt.Errorf("decode contents response: %w", err)
		}
		return body.SHA, nil
	case http.StatusNotFound:
		return "", nil
	default:
		return "", fmt.Errorf("unexpected status %d: %s", resp.StatusCode, readBody(resp))
	}
}

type putFileRequest struct {
	Message string `json:"message"`
	Content string `json:"content"`
	Branch  string `json:"branch"`
	SHA     string `json:"sha,omitempty"`
}

func (c *Client) putFile(ctx context.Context, repoPath string, content []byte, message, sha string) error {
	url := fmt.Sprintf("%s/repos/%s/contents/%s", c.baseURL, c.repo, repoPath)
	payload, err := json.Marshal(putFileRequest{
		Message: message,
		Content: base64.StdEncoding.EncodeToString(content),
		Branch:  "main",
		SHA:     sha,
	})
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPut, url, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	c.setHeaders(req)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return fmt.Errorf("unexpected status %d: %s", resp.StatusCode, readBody(resp))
	}
	return nil
}

func (c *Client) setHeaders(req *http.Request) {
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
}

func readBody(resp *http.Response) string {
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	return string(data)
}
