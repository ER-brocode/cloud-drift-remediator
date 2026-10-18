package remediator

import (
	"fmt"
	"time"

	"github.com/ER-brocode/cloud-drift-remediator/pkg/model"
)

// Planner generates an actionable remediation plan from detected drift.
type Planner struct {
	policy *Policy
}

// NewPlanner initializes a plan generator with safety policies.
func NewPlanner(policy *Policy) *Planner {
	if policy == nil {
		policy = DefaultPolicy()
	}
	return &Planner{policy: policy}
}

// GeneratePlan constructs the sequence of remediation steps and calculates blast radius.
func (p *Planner) GeneratePlan(report *model.DriftReport, dryRun bool) (*model.RemediationPlan, error) {
	if report == nil {
		return nil, fmt.Errorf("drift report cannot be nil")
	}

	planID := fmt.Sprintf("plan-%d", time.Now().UnixNano())
	plan := &model.RemediationPlan{
		PlanID:    planID,
		CreatedAt: time.Now(),
		DryRun:    dryRun,
	}

	blastScore := 0
	anyRequiresApproval := false

	for i, drift := range report.Drifts {
		action, requiresManual, reason := p.policy.Evaluate(drift)

		// Calculate blast radius contribution
		stepScore := drift.Severity.Weight()
		if action == model.ActionRecreate || action == model.ActionDelete {
			stepScore *= 2
		}
		blastScore += stepScore

		if requiresManual {
			anyRequiresApproval = true
		}

		stepID := fmt.Sprintf("step-%s-%d", drift.ResourceID, i+1)
		step := &model.RemediationStep{
			StepID:         stepID,
			ResourceID:     drift.ResourceID,
			ResourceType:   drift.ResourceType,
			Provider:       drift.Provider,
			Action:         action,
			Severity:       drift.Severity,
			TargetChanges:  drift.Differences,
			Status:         model.StatusPending,
			RequiresManual: requiresManual,
		}

		if dryRun {
			step.Status = model.StatusDryRun
		}

		// Generate inverse rollback plan if live resource exists
		if drift.ActualResource != nil && action == model.ActionUpdate {
			prevAttrs := make(map[string]interface{})
			for _, diff := range drift.Differences {
				prevAttrs[diff.Path] = diff.ActualValue
			}
			step.RollbackPlan = &model.RollbackStep{
				StepID:         fmt.Sprintf("rollback-%s", stepID),
				Action:         model.ActionUpdate,
				PreviousState:  prevAttrs,
				TargetResource: drift.ActualResource.Copy(),
			}
		}

		// If resource was missing and action is Recreate, rollback is to delete
		if action == model.ActionRecreate && drift.DriftType == model.DriftTypeMissingInLive {
			step.RollbackPlan = &model.RollbackStep{
				StepID:         fmt.Sprintf("rollback-%s", stepID),
				Action:         model.ActionDelete,
				TargetResource: drift.DesiredResource.Copy(),
			}
		}

		_ = reason
		plan.Steps = append(plan.Steps, step)
	}

	plan.TotalSteps = len(plan.Steps)
	plan.BlastRadiusScore = blastScore

	// Guardrail: if blast radius exceeds policy threshold, gate on approval
	if blastScore > p.policy.MaxBlastRadius {
		anyRequiresApproval = true
	}

	plan.RequiresApproval = anyRequiresApproval
	return plan, nil
}
