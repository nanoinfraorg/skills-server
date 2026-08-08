package github

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestPublishFiles_CreatesNewFileWithoutSHA(t *testing.T) {
	var putBody putFileRequest
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			w.WriteHeader(http.StatusNotFound) // file does not exist yet
		case http.MethodPut:
			if err := json.NewDecoder(r.Body).Decode(&putBody); err != nil {
				t.Errorf("decode put body: %v", err)
			}
			if r.Header.Get("Authorization") != "Bearer test-token" {
				t.Errorf("missing/incorrect auth header: %q", r.Header.Get("Authorization"))
			}
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"content":{"sha":"newsha"}}`))
		default:
			t.Errorf("unexpected method %s", r.Method)
		}
	}))
	defer server.Close()

	client := New("test-token", "nanoinfraorg/skills", WithBaseURL(server.URL))
	err := client.PublishFiles(context.Background(), "my-skill", []File{
		{Path: "SKILL.md", Content: []byte("---\nname: my-skill\n---\n")},
	}, "Publish my-skill v1 via skills-server")
	if err != nil {
		t.Fatalf("publish files: %v", err)
	}

	if putBody.SHA != "" {
		t.Errorf("expected no sha for a new file, got %q", putBody.SHA)
	}
	if putBody.Branch != "main" {
		t.Errorf("branch = %q, want main", putBody.Branch)
	}
	decoded, err := base64.StdEncoding.DecodeString(putBody.Content)
	if err != nil {
		t.Fatalf("decode content: %v", err)
	}
	if string(decoded) != "---\nname: my-skill\n---\n" {
		t.Errorf("decoded content = %q", decoded)
	}
}

func TestPublishFiles_UpdatesExistingFileWithSHA(t *testing.T) {
	var putBody putFileRequest
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"sha":"existing-sha"}`))
		case http.MethodPut:
			_ = json.NewDecoder(r.Body).Decode(&putBody)
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{}`))
		}
	}))
	defer server.Close()

	client := New("test-token", "nanoinfraorg/skills", WithBaseURL(server.URL))
	err := client.PublishFiles(context.Background(), "my-skill", []File{
		{Path: "SKILL.md", Content: []byte("updated")},
	}, "Publish my-skill v2 via skills-server")
	if err != nil {
		t.Fatalf("publish files: %v", err)
	}
	if putBody.SHA != "existing-sha" {
		t.Errorf("sha = %q, want existing-sha", putBody.SHA)
	}
}

func TestPublishFiles_PutFailurePropagates(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			w.WriteHeader(http.StatusNotFound)
		case http.MethodPut:
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte("boom"))
		}
	}))
	defer server.Close()

	client := New("test-token", "nanoinfraorg/skills", WithBaseURL(server.URL))
	err := client.PublishFiles(context.Background(), "my-skill", []File{
		{Path: "SKILL.md", Content: []byte("x")},
	}, "message")
	if err == nil {
		t.Fatal("expected error from a failing PUT, got nil")
	}
}
