package tests

import (
	"testing"

	"github.com/ER-brocode/cloud-drift-remediator/pkg/diff"
	"github.com/ER-brocode/cloud-drift-remediator/pkg/model"
)

func TestDriftEngine_ModifiedResource_CriticalSeverity(t *testing.T) {
	engine := diff.NewDriftEngine(nil)

	desired := []*model.Resource{
		{
			ID:       "sg-prod-web",
			Type:     model.AWSsecurityGroup,
			Provider: model.ProviderAWS,
			Region:   "us-east-1",
			Attributes: map[string]interface{}{
				"ingress": []interface{}{
					map[string]interface{}{
						"cidr_blocks": []interface{}{"10.0.0.0/16"},
						"from_port":   443,
						"to_port":     443,
						"protocol":    "tcp",
					},
				},
			},
		},
	}

	// Live cloud was altered to open port 443 to the world (0.0.0.0/0)
	live := []*model.Resource{
		{
			ID:       "sg-prod-web",
			Type:     model.AWSsecurityGroup,
			Provider: model.ProviderAWS,
			Region:   "us-east-1",
			Attributes: map[string]interface{}{
				"ingress": []interface{}{
					map[string]interface{}{
						"cidr_blocks": []interface{}{"0.0.0.0/0"},
						"from_port":   443,
						"to_port":     443,
						"protocol":    "tcp",
					},
				},
			},
		},
	}

	report, err := engine.DetectDrift(desired, live)
	if err != nil {
		t.Fatalf("Failed to detect drift: %v", err)
	}

	if report.TotalDrifted != 1 {
		t.Fatalf("Expected 1 drifted resource, got %d", report.TotalDrifted)
	}

	drift := report.Drifts[0]
	if drift.DriftType != model.DriftTypeModified {
		t.Errorf("Expected drift type MODIFIED, got %s", drift.DriftType)
	}

	if drift.Severity != model.SeverityCritical {
		t.Errorf("Expected Critical severity for 0.0.0.0/0 rule exposure, got %s", drift.Severity)
	}
}

func TestDriftEngine_MissingInLive(t *testing.T) {
	engine := diff.NewDriftEngine(nil)

	desired := []*model.Resource{
		{
			ID:       "s3-critical-backup",
			Type:     model.AWSs3Bucket,
			Provider: model.ProviderAWS,
			Region:   "us-east-1",
			Attributes: map[string]interface{}{
				"bucket": "s3-critical-backup",
			},
		},
	}

	// Live cloud is empty (bucket was deleted out-of-band)
	live := []*model.Resource{}

	report, err := engine.DetectDrift(desired, live)
	if err != nil {
		t.Fatalf("Failed to detect drift: %v", err)
	}

	if report.TotalDrifted != 1 {
		t.Fatalf("Expected 1 drifted resource, got %d", report.TotalDrifted)
	}

	drift := report.Drifts[0]
	if drift.DriftType != model.DriftTypeMissingInLive {
		t.Errorf("Expected drift type MISSING_IN_LIVE, got %s", drift.DriftType)
	}
}

func TestDriftEngine_UnmanagedInLive_ShadowIT(t *testing.T) {
	engine := diff.NewDriftEngine(nil)

	desired := []*model.Resource{}

	// Rogue compute instance spun up manually in cloud
	live := []*model.Resource{
		{
			ID:       "i-rogue12345678",
			Type:     model.AWSec2Instance,
			Provider: model.ProviderAWS,
			Region:   "us-west-2",
			Attributes: map[string]interface{}{
				"instance_type": "c5.4xlarge",
			},
		},
	}

	report, err := engine.DetectDrift(desired, live)
	if err != nil {
		t.Fatalf("Failed to detect drift: %v", err)
	}

	if report.TotalDrifted != 1 {
		t.Fatalf("Expected 1 drifted resource, got %d", report.TotalDrifted)
	}

	drift := report.Drifts[0]
	if drift.DriftType != model.DriftTypeUnmanagedInLive {
		t.Errorf("Expected drift type UNMANAGED_IN_LIVE, got %s", drift.DriftType)
	}
}

func TestDriftEngine_InSync(t *testing.T) {
	engine := diff.NewDriftEngine(nil)

	desired := []*model.Resource{
		{
			ID:       "s3-app-store",
			Type:     model.AWSs3Bucket,
			Provider: model.ProviderAWS,
			Attributes: map[string]interface{}{
				"bucket": "s3-app-store",
				"acl":    "private",
			},
		},
	}

	live := []*model.Resource{
		{
			ID:       "s3-app-store",
			Type:     model.AWSs3Bucket,
			Provider: model.ProviderAWS,
			Attributes: map[string]interface{}{
				"bucket": "s3-app-store",
				"acl":    "private",
			},
		},
	}

	report, err := engine.DetectDrift(desired, live)
	if err != nil {
		t.Fatalf("Failed to detect drift: %v", err)
	}

	if report.TotalDrifted != 0 {
		t.Errorf("Expected 0 drifts for identical resources, got %d", report.TotalDrifted)
	}
}
