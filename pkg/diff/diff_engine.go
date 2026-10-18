package diff

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/ER-brocode/cloud-drift-remediator/pkg/model"
)

// DriftEngine coordinates resource mapping and discrepancy detection.
type DriftEngine struct {
	opts *DiffOptions
}

// NewDriftEngine creates a new drift detection engine with the supplied options.
func NewDriftEngine(opts *DiffOptions) *DriftEngine {
	if opts == nil {
		opts = DefaultDiffOptions()
	}
	return &DriftEngine{opts: opts}
}

// DetectDrift compares desired IaC infrastructure against live cloud discovery.
func (e *DriftEngine) DetectDrift(desired, live []*model.Resource) (*model.DriftReport, error) {
	startTime := time.Now()

	desiredMap := make(map[string]*model.Resource)
	for _, r := range desired {
		desiredMap[r.ID] = r
	}

	liveMap := make(map[string]*model.Resource)
	for _, r := range live {
		liveMap[r.ID] = r
	}

	report := &model.DriftReport{
		ReportID:       fmt.Sprintf("drift-%d", time.Now().UnixNano()),
		GeneratedAt:    startTime,
		TotalDesired:   len(desired),
		TotalLive:      len(live),
		SeverityCounts: make(map[model.DriftSeverity]int),
		Drifts:         make([]*model.ResourceDrift, 0),
	}

	// 1. Evaluate Desired Resources (Modified or Missing in Live)
	for id, desRes := range desiredMap {
		liveRes, exists := liveMap[id]

		if !exists {
			// Resource is completely absent from live environment
			drift := &model.ResourceDrift{
				ResourceID:      id,
				ResourceType:    desRes.Type,
				Provider:        desRes.Provider,
				Region:          desRes.Region,
				DriftType:       model.DriftTypeMissingInLive,
				Severity:        model.SeverityHigh,
				DesiredResource: desRes,
				ActualResource:  nil,
				DetectedAt:      time.Now(),
				Differences: []model.FieldDiff{
					{
						Path:         "resource",
						DesiredValue: "PRESENT",
						ActualValue:  "DELETED_OR_ABSENT",
						Severity:     model.SeverityHigh,
						Reason:       "Resource defined in IaC state was deleted or not found in cloud provider",
					},
				},
			}
			report.Drifts = append(report.Drifts, drift)
			report.SeverityCounts[model.SeverityHigh]++
			continue
		}

		// Resource exists in both -> perform deep AST attribute diff
		walker := NewASTWalker(desRes.Type, e.opts)
		fieldDiffs := walker.Compare(desRes.Attributes, liveRes.Attributes)

		if len(fieldDiffs) > 0 {
			highestSev := model.SeverityLow
			for _, d := range fieldDiffs {
				highestSev = MaxSeverity(highestSev, d.Severity)
			}

			drift := &model.ResourceDrift{
				ResourceID:      id,
				ResourceType:    desRes.Type,
				Provider:        desRes.Provider,
				Region:          desRes.Region,
				DriftType:       model.DriftTypeModified,
				Severity:        highestSev,
				Differences:     fieldDiffs,
				DesiredResource: desRes,
				ActualResource:  liveRes,
				DetectedAt:      time.Now(),
			}
			report.Drifts = append(report.Drifts, drift)
			report.SeverityCounts[highestSev]++
		}
	}

	// 2. Evaluate Unmanaged / Rogue Live Resources
	for id, liveRes := range liveMap {
		if _, exists := desiredMap[id]; !exists {
			drift := &model.ResourceDrift{
				ResourceID:      id,
				ResourceType:    liveRes.Type,
				Provider:        liveRes.Provider,
				Region:          liveRes.Region,
				DriftType:       model.DriftTypeUnmanagedInLive,
				Severity:        model.SeverityMedium,
				DesiredResource: nil,
				ActualResource:  liveRes,
				DetectedAt:      time.Now(),
				Differences: []model.FieldDiff{
					{
						Path:         "management",
						DesiredValue: "UNTRACKED",
						ActualValue:  "DISCOVERED_IN_LIVE",
						Severity:     model.SeverityMedium,
						Reason:       "Rogue infrastructure created out-of-band without IaC tracking",
					},
				},
			}
			report.Drifts = append(report.Drifts, drift)
			report.SeverityCounts[model.SeverityMedium]++
		}
	}

	report.TotalDrifted = len(report.Drifts)
	report.ExecutionTimeMs = time.Since(startTime).Milliseconds()

	return report, nil
}

// FormatSARIF converts the drift report to GitHub-compatible SARIF JSON format.
func (e *DriftEngine) FormatSARIF(report *model.DriftReport) ([]byte, error) {
	type SarifRule struct {
		ID               string `json:"id"`
		ShortDescription struct {
			Text string `json:"text"`
		} `json:"shortDescription"`
	}

	type SarifMessage struct {
		Text string `json:"text"`
	}

	type SarifResult struct {
		RuleID  string       `json:"ruleId"`
		Level   string       `json:"level"`
		Message SarifMessage `json:"message"`
	}

	type SarifRun struct {
		Tool struct {
			Driver struct {
				Name    string      `json:"name"`
				Version string      `json:"version"`
				Rules   []SarifRule `json:"rules"`
			} `json:"driver"`
		} `json:"tool"`
		Results []SarifResult `json:"results"`
	}

	type SarifDoc struct {
		Version string     `json:"version"`
		Schema  string     `json:"$schema"`
		Runs    []SarifRun `json:"runs"`
	}

	var results []SarifResult
	for _, d := range report.Drifts {
		level := "warning"
		if d.Severity == model.SeverityCritical || d.Severity == model.SeverityHigh {
			level = "error"
		} else if d.Severity == model.SeverityInfo {
			level = "note"
		}

		msg := fmt.Sprintf("[%s] %s (%s) drifted in %s: %s", d.Severity, d.ResourceID, d.ResourceType, d.Provider, d.DriftType)
		results = append(results, SarifResult{
			RuleID:  fmt.Sprintf("DRIFT_%s", d.DriftType),
			Level:   level,
			Message: SarifMessage{Text: msg},
		})
	}

	doc := SarifDoc{
		Version: "2.1.0",
		Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
		Runs: []SarifRun{
			{
				Tool: struct {
					Driver struct {
						Name    string      `json:"name"`
						Version string      `json:"version"`
						Rules   []SarifRule `json:"rules"`
					} `json:"driver"`
				}{
					Driver: struct {
						Name    string      `json:"name"`
						Version string      `json:"version"`
						Rules   []SarifRule `json:"rules"`
					}{
						Name:    "cloud-drift-remediator",
						Version: "1.0.0",
						Rules: []SarifRule{
							{
								ID: "DRIFT_MODIFIED",
								ShortDescription: struct {
									Text string `json:"text"`
								}{Text: "Resource attributes diverge from desired IaC state"},
							},
							{
								ID: "DRIFT_MISSING_IN_LIVE",
								ShortDescription: struct {
									Text string `json:"text"`
								}{Text: "IaC declared resource was deleted or absent in cloud provider"},
							},
							{
								ID: "DRIFT_UNMANAGED_IN_LIVE",
								ShortDescription: struct {
									Text string `json:"text"`
								}{Text: "Rogue or unmanaged resource discovered in live cloud"},
							},
						},
					},
				},
				Results: results,
			},
		},
	}

	return json.MarshalIndent(doc, "", "  ")
}
