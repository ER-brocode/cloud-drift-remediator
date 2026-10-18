package scanner

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/ER-brocode/cloud-drift-remediator/pkg/model"
)

// TFStateV4 matches the standard Terraform / OpenTofu v4 state file format.
type TFStateV4 struct {
	Version          int              `json:"version"`
	TerraformVersion string           `json:"terraform_version"`
	Serial           int64            `json:"serial"`
	Lineage          string           `json:"lineage"`
	Resources        []TFResourceMeta `json:"resources"`
}

// TFResourceMeta represents a managed or data resource definition in state.
type TFResourceMeta struct {
	Mode      string               `json:"mode"`
	Type      string               `json:"type"`
	Name      string               `json:"name"`
	Provider  string               `json:"provider"`
	Instances []TFResourceInstance `json:"instances"`
}

// TFResourceInstance represents an instantiated resource in state.
type TFResourceInstance struct {
	IndexKey            interface{}            `json:"index_key,omitempty"`
	SchemaVersion       int                    `json:"schema_version"`
	Attributes          map[string]interface{} `json:"attributes"`
	AttributesFlat      map[string]string      `json:"attributes_flat,omitempty"`
	SensitiveAttributes []interface{}          `json:"sensitive_attributes,omitempty"`
}

// StateParser defines the parser interface for IaC state files.
type StateParser interface {
	ParseFile(path string) ([]*model.Resource, error)
	ParseReader(r io.Reader) ([]*model.Resource, error)
	ParseBytes(data []byte) ([]*model.Resource, error)
}

// TerraformStateParser implements StateParser for Terraform and OpenTofu states.
type TerraformStateParser struct{}

// NewTerraformStateParser constructs a new parser.
func NewTerraformStateParser() *TerraformStateParser {
	return &TerraformStateParser{}
}

// ParseFile reads and parses a state file from local disk.
func (p *TerraformStateParser) ParseFile(path string) ([]*model.Resource, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read state file at %s: %w", path, err)
	}
	return p.ParseBytes(data)
}

// ParseReader reads state JSON from an io.Reader stream.
func (p *TerraformStateParser) ParseReader(r io.Reader) ([]*model.Resource, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("failed to read state stream: %w", err)
	}
	return p.ParseBytes(data)
}

// ParseBytes parses raw JSON state into normalized model.Resource slices.
func (p *TerraformStateParser) ParseBytes(data []byte) ([]*model.Resource, error) {
	var state TFStateV4
	if err := json.Unmarshal(data, &state); err != nil {
		return nil, fmt.Errorf("invalid terraform state json: %w", err)
	}

	if state.Version != 4 {
		return nil, fmt.Errorf("unsupported state version %d, expected version 4", state.Version)
	}

	var normalized []*model.Resource

	for _, resMeta := range state.Resources {
		// Only process managed resources (skip data sources for drift detection)
		if resMeta.Mode != "managed" {
			continue
		}

		provider := inferProvider(resMeta.Provider, resMeta.Type)

		for _, inst := range resMeta.Instances {
			attrs := inst.Attributes
			if attrs == nil {
				attrs = make(map[string]interface{})
			}

			// Extract resource identity
			resID := extractResourceID(attrs, resMeta.Type, resMeta.Name)
			region := extractRegion(attrs, provider)
			tags := extractTags(attrs)

			// Clean attributes clone
			attrsClone := make(map[string]interface{}, len(attrs))
			for k, v := range attrs {
				attrsClone[k] = v
			}

			normalizedRes := &model.Resource{
				ID:          resID,
				Type:        model.ResourceType(resMeta.Type),
				Provider:    provider,
				Region:      region,
				Name:        resMeta.Name,
				StateSource: "terraform_state_v4",
				Attributes:  attrsClone,
				Tags:        tags,
				Metadata: map[string]string{
					"terraform_version": state.TerraformVersion,
					"schema_version":    fmt.Sprintf("%d", inst.SchemaVersion),
					"provider_fqn":      resMeta.Provider,
				},
			}

			normalized = append(normalized, normalizedRes)
		}
	}

	return normalized, nil
}

// inferProvider maps provider string or resource type prefix to CloudProvider enum.
func inferProvider(providerStr, resType string) model.CloudProvider {
	lowerProv := strings.ToLower(providerStr)
	lowerType := strings.ToLower(resType)

	if strings.Contains(lowerProv, "aws") || strings.HasPrefix(lowerType, "aws_") {
		return model.ProviderAWS
	}
	if strings.Contains(lowerProv, "google") || strings.HasPrefix(lowerType, "google_") {
		return model.ProviderGCP
	}
	if strings.Contains(lowerProv, "azurerm") || strings.Contains(lowerProv, "azure") || strings.HasPrefix(lowerType, "azurerm_") {
		return model.ProviderAzure
	}

	return model.ProviderAWS
}

// extractResourceID extracts canonical ID from attributes.
func extractResourceID(attrs map[string]interface{}, resType, defaultName string) string {
	if val, ok := attrs["id"]; ok {
		if s, ok := val.(string); ok && s != "" {
			return s
		}
	}
	if val, ok := attrs["arn"]; ok {
		if s, ok := val.(string); ok && s != "" {
			return s
		}
	}
	if val, ok := attrs["name"]; ok {
		if s, ok := val.(string); ok && s != "" {
			return s
		}
	}
	return fmt.Sprintf("%s-%s", resType, defaultName)
}

// extractRegion extracts cloud region or returns default.
func extractRegion(attrs map[string]interface{}, provider model.CloudProvider) string {
	if val, ok := attrs["region"]; ok {
		if s, ok := val.(string); ok && s != "" {
			return s
		}
	}
	if val, ok := attrs["location"]; ok {
		if s, ok := val.(string); ok && s != "" {
			return s
		}
	}
	switch provider {
	case model.ProviderAWS:
		return "us-east-1"
	case model.ProviderGCP:
		return "us-central1"
	case model.ProviderAzure:
		return "eastus"
	default:
		return "global"
	}
}

// extractTags standardizes tags map from attributes.
func extractTags(attrs map[string]interface{}) map[string]string {
	result := make(map[string]string)
	if val, ok := attrs["tags"]; ok && val != nil {
		if rawMap, ok := val.(map[string]interface{}); ok {
			for k, v := range rawMap {
				if str, ok := v.(string); ok {
					result[k] = str
				} else {
					result[k] = fmt.Sprintf("%v", v)
				}
			}
		}
	}
	if val, ok := attrs["labels"]; ok && val != nil {
		if rawMap, ok := val.(map[string]interface{}); ok {
			for k, v := range rawMap {
				if str, ok := v.(string); ok {
					result[k] = str
				} else {
					result[k] = fmt.Sprintf("%v", v)
				}
			}
		}
	}
	return result
}
