package tests

import (
	"path/filepath"
	"testing"

	"github.com/ER-brocode/cloud-drift-remediator/pkg/model"
	"github.com/ER-brocode/cloud-drift-remediator/pkg/scanner"
)

func TestTerraformStateParser(t *testing.T) {
	fixturePath := filepath.Join("fixtures", "terraform.tfstate")
	parser := scanner.NewTerraformStateParser()

	resources, err := parser.ParseFile(fixturePath)
	if err != nil {
		t.Fatalf("Failed to parse fixture state file: %v", err)
	}

	if len(resources) != 2 {
		t.Fatalf("Expected 2 resources, got %d", len(resources))
	}

	// Verify Security Group
	sg := resources[0]
	if sg.Type != model.AWSsecurityGroup {
		t.Errorf("Expected resource type %s, got %s", model.AWSsecurityGroup, sg.Type)
	}
	if sg.ID != "sg-0abcd1234ef567890" {
		t.Errorf("Expected sg ID sg-0abcd1234ef567890, got %s", sg.ID)
	}
	if sg.Provider != model.ProviderAWS {
		t.Errorf("Expected provider %s, got %s", model.ProviderAWS, sg.Provider)
	}
	if sg.Tags["Environment"] != "production" {
		t.Errorf("Expected Environment tag 'production', got '%s'", sg.Tags["Environment"])
	}

	// Verify S3 Bucket
	s3 := resources[1]
	if s3.Type != model.AWSs3Bucket {
		t.Errorf("Expected resource type %s, got %s", model.AWSs3Bucket, s3.Type)
	}
	if s3.ID != "prod-customer-vault-bucket-us-east-1" {
		t.Errorf("Expected bucket ID prod-customer-vault-bucket-us-east-1, got %s", s3.ID)
	}
}

func TestTerraformStateParser_InvalidVersion(t *testing.T) {
	invalidJSON := []byte(`{"version": 3, "terraform_version": "0.11.0"}`)
	parser := scanner.NewTerraformStateParser()
	_, err := parser.ParseBytes(invalidJSON)
	if err == nil {
		t.Fatalf("Expected error on unsupported state version 3, got nil")
	}
}
