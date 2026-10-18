package tests

import (
	"testing"

	"github.com/ER-brocode/cloud-drift-remediator/pkg/diff"
	"github.com/ER-brocode/cloud-drift-remediator/pkg/model"
)

func TestASTWalker_TypeCoercion(t *testing.T) {
	opts := diff.DefaultDiffOptions()
	walker := diff.NewASTWalker(model.AWSsecurityGroup, opts)

	desired := map[string]interface{}{
		"port":    80,
		"enabled": true,
		"ratio":   0.5,
	}

	// Live cloud returned stringified representations
	actual := map[string]interface{}{
		"port":    "80",
		"enabled": "true",
		"ratio":   "0.5",
	}

	diffs := walker.Compare(desired, actual)
	if len(diffs) != 0 {
		t.Errorf("Expected 0 diffs after type coercion, got %d: %+v", len(diffs), diffs)
	}
}

func TestASTWalker_SensitiveFieldMasking(t *testing.T) {
	opts := diff.DefaultDiffOptions()
	opts.MaskSensitive = true
	walker := diff.NewASTWalker(model.AWSiamRole, opts)

	desired := map[string]interface{}{
		"db_password":     "SuperSecretPass123!",
		"api_token":       "ghp_test_secret_token",
		"normal_username": "dbadmin",
	}

	actual := map[string]interface{}{
		"db_password":     "OldLeakedPass456!",
		"api_token":       "ghp_old_token",
		"normal_username": "dbadmin_modified",
	}

	diffs := walker.Compare(desired, actual)
	if len(diffs) != 3 {
		t.Fatalf("Expected 3 diffs, got %d", len(diffs))
	}

	for _, d := range diffs {
		if d.Path == "db_password" || d.Path == "api_token" {
			if !d.Sensitive {
				t.Errorf("Expected path %s to be flagged sensitive", d.Path)
			}
			if d.DesiredValue != "********" || d.ActualValue != "********" {
				t.Errorf("Expected masked value for sensitive field %s, got Desired: %v, Actual: %v",
					d.Path, d.DesiredValue, d.ActualValue)
			}
		}
	}
}

func TestASTWalker_IgnorePaths(t *testing.T) {
	opts := diff.DefaultDiffOptions()
	walker := diff.NewASTWalker(model.AWSs3Bucket, opts)

	desired := map[string]interface{}{
		"id":         "bucket-123",
		"arn":        "arn:aws:s3:::bucket-123",
		"etag":       "abcde12345",
		"versioning": true,
	}

	actual := map[string]interface{}{
		"id":         "bucket-123",
		"arn":        "arn:aws:s3:::bucket-123-cloud",
		"etag":       "new-cloud-etag-9999",
		"versioning": true,
	}

	diffs := walker.Compare(desired, actual)
	if len(diffs) != 0 {
		t.Errorf("Expected cloud dynamic fields (arn, etag) to be ignored, got diffs: %+v", diffs)
	}
}

func TestDiffEngine_SARIFGeneration(t *testing.T) {
	engine := diff.NewDriftEngine(nil)

	desired := []*model.Resource{
		{
			ID:       "sg-test-1",
			Type:     model.AWSsecurityGroup,
			Provider: model.ProviderAWS,
			Attributes: map[string]interface{}{
				"description": "Safe SG",
			},
		},
	}

	live := []*model.Resource{
		{
			ID:       "sg-test-1",
			Type:     model.AWSsecurityGroup,
			Provider: model.ProviderAWS,
			Attributes: map[string]interface{}{
				"description": "Drifted SG description",
			},
		},
	}

	report, err := engine.DetectDrift(desired, live)
	if err != nil {
		t.Fatalf("Unexpected drift detection error: %v", err)
	}

	sarifBytes, err := engine.FormatSARIF(report)
	if err != nil {
		t.Fatalf("Failed to format SARIF: %v", err)
	}

	if len(sarifBytes) == 0 {
		t.Errorf("SARIF output was empty")
	}
}
