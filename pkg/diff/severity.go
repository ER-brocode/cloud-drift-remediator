package diff

import (
	"strings"

	"github.com/ER-brocode/cloud-drift-remediator/pkg/model"
)

// ClassifyFieldSeverity determines the drift severity based on resource type, attribute path, and values.
func ClassifyFieldSeverity(resType model.ResourceType, path string, desired, actual interface{}) (model.DriftSeverity, string) {
	lowerPath := strings.ToLower(path)

	// Security-critical paths
	if strings.Contains(lowerPath, "cidr_blocks") || strings.Contains(lowerPath, "ingress") {
		// Detect opening to the world
		if isOpenToWorld(actual) && !isOpenToWorld(desired) {
			return model.SeverityCritical, "Inbound security rule was broadened to allow public ingress (0.0.0.0/0)"
		}
		return model.SeverityHigh, "Network firewall / security group ingress rules modified"
	}

	if strings.Contains(lowerPath, "acl") || strings.Contains(lowerPath, "public_access_block") || strings.Contains(lowerPath, "bucket_policy") {
		return model.SeverityCritical, "Storage public access control configuration modified"
	}

	if strings.Contains(lowerPath, "assume_role_policy") || strings.Contains(lowerPath, "policy") {
		return model.SeverityCritical, "IAM permission or trust policy modified"
	}

	if strings.Contains(lowerPath, "encryption") || strings.Contains(lowerPath, "kms_key_id") || strings.Contains(lowerPath, "server_side_encryption") {
		return model.SeverityHigh, "At-rest encryption policy or KMS key drifted"
	}

	if strings.Contains(lowerPath, "instance_type") || strings.Contains(lowerPath, "machine_type") {
		return model.SeverityHigh, "Compute sizing/capacity modified out-of-band"
	}

	if strings.Contains(lowerPath, "versioning") || strings.Contains(lowerPath, "logging") {
		return model.SeverityMedium, "Audit logging or data versioning configuration changed"
	}

	if strings.Contains(lowerPath, "tags") || strings.Contains(lowerPath, "labels") {
		return model.SeverityLow, "Resource metadata tags or labels drifted"
	}

	if strings.Contains(lowerPath, "description") || strings.Contains(lowerPath, "comment") {
		return model.SeverityInfo, "Informational description or comment changed"
	}

	return model.SeverityMedium, "Infrastructure configuration drifted"
}

// isOpenToWorld checks if a CIDR or network definition exposes 0.0.0.0/0.
func isOpenToWorld(val interface{}) bool {
	if val == nil {
		return false
	}
	switch v := val.(type) {
	case string:
		return strings.Contains(v, "0.0.0.0/0") || strings.Contains(v, "::/0")
	case []interface{}:
		for _, item := range v {
			if s, ok := item.(string); ok && (strings.Contains(s, "0.0.0.0/0") || strings.Contains(s, "::/0")) {
				return true
			}
		}
	case []string:
		for _, s := range v {
			if strings.Contains(s, "0.0.0.0/0") || strings.Contains(s, "::/0") {
				return true
			}
		}
	}
	return false
}

// MaxSeverity returns the highest severity among two.
func MaxSeverity(a, b model.DriftSeverity) model.DriftSeverity {
	if a.Weight() >= b.Weight() {
		return a
	}
	return b
}
