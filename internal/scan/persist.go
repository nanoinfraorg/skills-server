package scan

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/nanoinfraorg/skills-server/internal/store"
)

// BuildScanRow serializes report into a store.Scan row ready for
// store.Store.CreateScan, targeting either a pending submission or a
// published skill version. Centralizing this here (rather than in the api
// and scheduler packages separately, both of which need it) keeps the JSON
// shape of a persisted finding in one place.
func BuildScanRow(report Report, targetType store.ScanTargetType, targetID string, trigger store.ScanTrigger, scannedAt time.Time) (store.Scan, error) {
	hidden, err := json.Marshal(nonNilSlice(report.HiddenCharFindings))
	if err != nil {
		return store.Scan{}, fmt.Errorf("marshal hidden char findings: %w", err)
	}
	static, err := json.Marshal(nonNilSlice(report.StaticPatternFindings))
	if err != nil {
		return store.Scan{}, fmt.Errorf("marshal static pattern findings: %w", err)
	}

	sc := store.Scan{
		TargetType:                targetType,
		TargetID:                  targetID,
		Trigger:                   trigger,
		Verdict:                   store.ScanVerdict(report.Verdict),
		TextOnlyOK:                report.TextOnlyOK,
		HiddenCharsFindingsJSON:   string(hidden),
		StaticPatternFindingsJSON: string(static),
		ScannedAt:                 scannedAt,
	}
	if report.LLMAssessment != nil {
		llm, err := json.Marshal(report.LLMAssessment)
		if err != nil {
			return store.Scan{}, fmt.Errorf("marshal llm assessment: %w", err)
		}
		s := string(llm)
		sc.LLMAssessmentJSON = &s
	}
	return sc, nil
}

// nonNilSlice returns an empty (non-nil) slice in place of a nil one, so
// json.Marshal always produces "[]" rather than "null" for an empty
// findings list.
func nonNilSlice[T any](s []T) []T {
	if s == nil {
		return []T{}
	}
	return s
}
