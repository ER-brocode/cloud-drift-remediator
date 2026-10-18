package model

import (
	"encoding/json"
	"fmt"
	"time"
)

// CloudProvider identifies the target cloud provider.
type CloudProvider string

const (
	ProviderAWS   CloudProvider = "aws"
	ProviderGCP   CloudProvider = "gcp"
	ProviderAzure CloudProvider = "azure"
	ProviderMock  CloudProvider = "mock"
)

// ResourceType denotes the standardized cloud infrastructure resource kind.
type ResourceType string

const (
	// AWS Resource Types
	AWSec2Instance      ResourceType = "aws_instance"
	AWSs3Bucket         ResourceType = "aws_s3_bucket"
	AWSsecurityGroup    ResourceType = "aws_security_group"
	AWSiamRole          ResourceType = "aws_iam_role"
	AWSiamPolicy        ResourceType = "aws_iam_policy"
	AWSvpc              ResourceType = "aws_vpc"
	AWSsubnet           ResourceType = "aws_subnet"

	// GCP Resource Types
	GCPcomputeInstance  ResourceType = "google_compute_instance"
	GCPstorageBucket    ResourceType = "google_storage_bucket"
	GCPcomputeFirewall  ResourceType = "google_compute_firewall"

	// Azure Resource Types
	AzureVirtualMachine ResourceType = "azurerm_virtual_machine"
	AzureStorageAccount ResourceType = "azurerm_storage_account"
	AzureNSG            ResourceType = "azurerm_network_security_group"
)

// DriftSeverity classifies the operational and security risk of detected drift.
type DriftSeverity string

const (
	SeverityCritical DriftSeverity = "CRITICAL"
	SeverityHigh     DriftSeverity = "HIGH"
	SeverityMedium   DriftSeverity = "MEDIUM"
	SeverityLow      DriftSeverity = "LOW"
	SeverityInfo     DriftSeverity = "INFO"
)

// SeverityWeight provides a numeric comparison score for severities.
func (s DriftSeverity) Weight() int {
	switch s {
	case SeverityCritical:
		return 5
	case SeverityHigh:
		return 4
	case SeverityMedium:
		return 3
	case SeverityLow:
		return 2
	case SeverityInfo:
		return 1
	default:
		return 0
	}
}

// DriftType categorizes the fundamental category of discrepancy.
type DriftType string

const (
	// DriftTypeModified represents an attribute divergence between desired and actual.
	DriftTypeModified DriftType = "MODIFIED"
	// DriftTypeMissingInLive represents a resource defined in IaC but absent in live cloud.
	DriftTypeMissingInLive DriftType = "MISSING_IN_LIVE"
	// DriftTypeUnmanagedInLive represents rogue / shadow IT resources in cloud not managed by IaC.
	DriftTypeUnmanagedInLive DriftType = "UNMANAGED_IN_LIVE"
)

// Resource represents a normalized infrastructure resource.
type Resource struct {
	ID          string                 `json:"id"`
	Type        ResourceType           `json:"type"`
	Provider    CloudProvider          `json:"provider"`
	Region      string                 `json:"region"`
	Name        string                 `json:"name"`
	StateSource string                 `json:"state_source"` // e.g. "terraform_state", "opentofu_state", "live_api"
	Attributes  map[string]interface{} `json:"attributes"`
	Tags        map[string]string      `json:"tags"`
	Metadata    map[string]string      `json:"metadata,omitempty"`
}

// Copy returns a deep clone of the resource.
func (r *Resource) Copy() *Resource {
	if r == nil {
		return nil
	}
	raw, err := json.Marshal(r)
	if err != nil {
		return nil
	}
	var clone Resource
	if err := json.Unmarshal(raw, &clone); err != nil {
		return nil
	}
	return &clone
}

// FieldDiff defines an attribute-level difference.
type FieldDiff struct {
	Path         string        `json:"path"`
	DesiredValue interface{}   `json:"desired_value"`
	ActualValue  interface{}   `json:"actual_value"`
	Severity     DriftSeverity `json:"severity"`
	Sensitive    bool          `json:"sensitive"`
	Reason       string        `json:"reason,omitempty"`
}

// ResourceDrift records detected drift for a specific infrastructure entity.
type ResourceDrift struct {
	ResourceID      string        `json:"resource_id"`
	ResourceType    ResourceType  `json:"resource_type"`
	Provider        CloudProvider `json:"provider"`
	Region          string        `json:"region"`
	DriftType       DriftType     `json:"drift_type"`
	Severity        DriftSeverity `json:"severity"`
	Differences     []FieldDiff   `json:"differences"`
	DesiredResource *Resource     `json:"desired_resource,omitempty"`
	ActualResource  *Resource     `json:"actual_resource,omitempty"`
	DetectedAt      time.Time     `json:"detected_at"`
}

// DriftReport encapsulates a comprehensive drift inspection across providers.
type DriftReport struct {
	ReportID        string           `json:"report_id"`
	GeneratedAt     time.Time        `json:"generated_at"`
	TotalDesired    int              `json:"total_desired"`
	TotalLive       int              `json:"total_live"`
	TotalDrifted    int              `json:"total_drifted"`
	SeverityCounts  map[DriftSeverity]int `json:"severity_counts"`
	Drifts          []*ResourceDrift `json:"drifts"`
	ExecutionTimeMs int64            `json:"execution_time_ms"`
}

// RemediationActionType defines the operation required to bring live infrastructure in sync.
type RemediationActionType string

const (
	ActionUpdate    RemediationActionType = "UPDATE"
	ActionRecreate  RemediationActionType = "RECREATE"
	ActionDelete    RemediationActionType = "DELETE"
	ActionImport    RemediationActionType = "IMPORT"
	ActionAlertOnly RemediationActionType = "ALERT_ONLY"
	ActionRollback  RemediationActionType = "ROLLBACK"
)

// RemediationStatus defines the lifecycle status of a remediation step.
type RemediationStatus string

const (
	StatusPending   RemediationStatus = "PENDING"
	StatusApproved  RemediationStatus = "APPROVED"
	StatusRejected  RemediationStatus = "REJECTED"
	StatusDryRun    RemediationStatus = "DRY_RUN"
	StatusExecuting RemediationStatus = "EXECUTING"
	StatusSucceeded RemediationStatus = "SUCCEEDED"
	StatusFailed    RemediationStatus = "FAILED"
	StatusRolledBack RemediationStatus = "ROLLED_BACK"
)

// RemediationStep details an individual automated reconciliation task.
type RemediationStep struct {
	StepID         string                `json:"step_id"`
	ResourceID     string                `json:"resource_id"`
	ResourceType   ResourceType          `json:"resource_type"`
	Provider       CloudProvider         `json:"provider"`
	Action         RemediationActionType `json:"action"`
	Severity       DriftSeverity         `json:"severity"`
	TargetChanges  []FieldDiff           `json:"target_changes"`
	Status         RemediationStatus     `json:"status"`
	ErrorMessage   string                `json:"error_message,omitempty"`
	RollbackPlan   *RollbackStep         `json:"rollback_plan,omitempty"`
	RequiresManual bool                  `json:"requires_manual"`
	ExecutedAt     *time.Time            `json:"executed_at,omitempty"`
}

// RollbackStep provides the inverse operation to revert a remediation if failure occurs.
type RollbackStep struct {
	StepID         string                `json:"step_id"`
	Action         RemediationActionType `json:"action"`
	PreviousState  map[string]interface{}`json:"previous_state"`
	TargetResource *Resource             `json:"target_resource"`
}

// RemediationPlan aggregates the sequence of steps, blast radius metrics, and policy safety checks.
type RemediationPlan struct {
	PlanID           string             `json:"plan_id"`
	CreatedAt        time.Time          `json:"created_at"`
	TotalSteps       int                `json:"total_steps"`
	BlastRadiusScore int                `json:"blast_radius_score"`
	RequiresApproval bool               `json:"requires_approval"`
	Approved         bool               `json:"approved"`
	ApprovedBy       string             `json:"approved_by,omitempty"`
	DryRun           bool               `json:"dry_run"`
	Steps            []*RemediationStep `json:"steps"`
}

// PrintSummary returns a human-readable summary of the drift report.
func (dr *DriftReport) PrintSummary() string {
	return fmt.Sprintf("Drift Report [%s]: %d Desired, %d Live, %d Drifted (Critical: %d, High: %d, Medium: %d, Low: %d, Info: %d)",
		dr.ReportID,
		dr.TotalDesired,
		dr.TotalLive,
		dr.TotalDrifted,
		dr.SeverityCounts[SeverityCritical],
		dr.SeverityCounts[SeverityHigh],
		dr.SeverityCounts[SeverityMedium],
		dr.SeverityCounts[SeverityLow],
		dr.SeverityCounts[SeverityInfo],
	)
}
