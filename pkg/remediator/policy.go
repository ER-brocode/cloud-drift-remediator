package remediator

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"

	"github.com/ER-brocode/cloud-drift-remediator/pkg/model"
)

// Policy defines guardrails and auto-reconciliation thresholds.
type Policy struct {
	Version            string                                          `json:"version"`
	AutoRemediate      bool                                            `json:"auto_remediate"`
	MaxBlastRadius     int                                             `json:"max_blast_radius"`
	RequireApproval    bool                                            `json:"require_approval"`
	AllowedSeverities  []model.DriftSeverity                           `json:"allowed_severities"`
	ProtectedResources []string                                        `json:"protected_resources"`
	ActionOverrides    map[model.ResourceType]model.RemediationActionType `json:"action_overrides"`
	Rules              []Rule                                          `json:"rules"`
	protectedRegexes   []*regexp.Regexp
}

// Rule defines specific condition matching for resource drift handling.
type Rule struct {
	Name         string                    `json:"name"`
	ResourceType model.ResourceType        `json:"resource_type"`
	DriftType    model.DriftType           `json:"drift_type"`
	Action       model.RemediationActionType `json:"action"`
	RequiresGate bool                      `json:"requires_gate"`
}

// DefaultPolicy returns a secure baseline policy suitable for enterprise production.
func DefaultPolicy() *Policy {
	return &Policy{
		Version:         "1.0",
		AutoRemediate:   true,
		MaxBlastRadius:  10,
		RequireApproval: false,
		AllowedSeverities: []model.DriftSeverity{
			model.SeverityCritical,
			model.SeverityHigh,
			model.SeverityMedium,
			model.SeverityLow,
			model.SeverityInfo,
		},
		ProtectedResources: []string{
			`.*production.*`,
			`.*prod.*db.*`,
			`.*vpc-.*`,
			`.*rds.*`,
		},
		ActionOverrides: map[model.ResourceType]model.RemediationActionType{
			model.AWSs3Bucket: model.ActionUpdate,
		},
	}
}

// LoadPolicy parses a JSON policy definition file.
func LoadPolicy(path string) (*Policy, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read policy file: %w", err)
	}
	var p Policy
	if err := json.Unmarshal(data, &p); err != nil {
		return nil, fmt.Errorf("failed to parse policy json: %w", err)
	}
	if err := p.Compile(); err != nil {
		return nil, err
	}
	return &p, nil
}

// Compile compiles the regular expressions inside the policy.
func (p *Policy) Compile() error {
	p.protectedRegexes = nil
	for _, pattern := range p.ProtectedResources {
		re, err := regexp.Compile(pattern)
		if err != nil {
			return fmt.Errorf("invalid protected resource regex '%s': %w", pattern, err)
		}
		p.protectedRegexes = append(p.protectedRegexes, re)
	}
	return nil
}

// IsProtected checks if a resource matches any protected regex.
func (p *Policy) IsProtected(resourceID, name string) bool {
	for _, re := range p.protectedRegexes {
		if re.MatchString(resourceID) || (name != "" && re.MatchString(name)) {
			return true
		}
	}
	return false
}

// Evaluate evaluates a detected resource drift against the policy.
// Returns (action, requiresManualApproval, reason).
func (p *Policy) Evaluate(drift *model.ResourceDrift) (model.RemediationActionType, bool, string) {
	resName := ""
	if drift.DesiredResource != nil {
		resName = drift.DesiredResource.Name
	} else if drift.ActualResource != nil {
		resName = drift.ActualResource.Name
	}

	// 1. Protected Resource Safety Guard
	if p.IsProtected(drift.ResourceID, resName) {
		// Protected resources are NEVER modified automatically if destruction/recreation is involved
		if drift.DriftType == model.DriftTypeMissingInLive || drift.DriftType == model.DriftTypeUnmanagedInLive {
			return model.ActionAlertOnly, true, fmt.Sprintf("Resource %s matches protected resource rule; automated action halted", drift.ResourceID)
		}
	}

	// 2. Global require approval check
	requiresApproval := p.RequireApproval

	// 3. Check custom rules
	for _, rule := range p.Rules {
		if rule.ResourceType == "" || rule.ResourceType == drift.ResourceType {
			if rule.DriftType == "" || rule.DriftType == drift.DriftType {
				return rule.Action, rule.RequiresGate || requiresApproval, fmt.Sprintf("Matched rule: %s", rule.Name)
			}
		}
	}

	// 4. Default drift type actions
	var action model.RemediationActionType
	switch drift.DriftType {
	case model.DriftTypeModified:
		action = model.ActionUpdate
	case model.DriftTypeMissingInLive:
		action = model.ActionRecreate
	case model.DriftTypeUnmanagedInLive:
		// Shadow IT rogue resource: default safe action is alert or import
		action = model.ActionAlertOnly
		requiresApproval = true
	default:
		action = model.ActionAlertOnly
	}

	// Check action overrides
	if override, ok := p.ActionOverrides[drift.ResourceType]; ok {
		action = override
	}

	// 5. Allowed severities check
	severityAllowed := false
	for _, s := range p.AllowedSeverities {
		if s == drift.Severity {
			severityAllowed = true
			break
		}
	}
	if !severityAllowed {
		return model.ActionAlertOnly, true, fmt.Sprintf("Severity %s is outside auto-remediation policy allowance", drift.Severity)
	}

	return action, requiresApproval, "Standard policy reconciliation path"
}
