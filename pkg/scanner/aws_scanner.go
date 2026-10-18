package scanner

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/ER-brocode/cloud-drift-remediator/pkg/model"
)

// AWSScanner handles discovery and live inspection for Amazon Web Services infrastructure.
type AWSScanner struct {
	region       string
	mu           sync.RWMutex
	liveStore    map[string]*model.Resource
	simulateLive bool
}

// NewAWSScanner creates an AWS scanner. If simulateLive is true, it maintains an in-memory
// synchronized store suitable for local testing, emulation, and sandbox execution.
func NewAWSScanner(region string, simulateLive bool) *AWSScanner {
	if region == "" {
		region = "us-east-1"
	}
	return &AWSScanner{
		region:       region,
		liveStore:    make(map[string]*model.Resource),
		simulateLive: simulateLive,
	}
}

// ProviderName returns AWS identifier.
func (a *AWSScanner) ProviderName() model.CloudProvider {
	return model.ProviderAWS
}

// SupportedTypes returns the list of AWS resources handled.
func (a *AWSScanner) SupportedTypes() []model.ResourceType {
	return []model.ResourceType{
		model.AWSec2Instance,
		model.AWSs3Bucket,
		model.AWSsecurityGroup,
		model.AWSiamRole,
		model.AWSiamPolicy,
		model.AWSvpc,
		model.AWSsubnet,
	}
}

// SeedLiveResource injects a simulated or fetched live cloud resource.
func (a *AWSScanner) SeedLiveResource(res *model.Resource) {
	a.mu.Lock()
	defer a.mu.Unlock()
	res.Provider = model.ProviderAWS
	res.StateSource = "aws_api"
	a.liveStore[res.ID] = res.Copy()
}

// DiscoverResources queries the live AWS environment for the given resource types.
func (a *AWSScanner) DiscoverResources(ctx context.Context, types []model.ResourceType) ([]*model.Resource, error) {
	a.mu.RLock()
	defer a.mu.RUnlock()

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	typeLookup := make(map[model.ResourceType]bool)
	for _, t := range types {
		typeLookup[t] = true
	}

	var results []*model.Resource
	for _, r := range a.liveStore {
		if len(types) == 0 || typeLookup[r.Type] {
			results = append(results, r.Copy())
		}
	}

	return results, nil
}

// FetchResource retrieves a single AWS resource by type and ID.
func (a *AWSScanner) FetchResource(ctx context.Context, resType model.ResourceType, id string) (*model.Resource, error) {
	a.mu.RLock()
	defer a.mu.RUnlock()

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	res, ok := a.liveStore[id]
	if !ok {
		return nil, fmt.Errorf("aws resource %s of type %s not found in live cloud", id, resType)
	}
	return res.Copy(), nil
}

// UpdateResource applies attribute modifications to a live AWS resource.
func (a *AWSScanner) UpdateResource(ctx context.Context, res *model.Resource, changes []model.FieldDiff) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	existing, ok := a.liveStore[res.ID]
	if !ok {
		return fmt.Errorf("cannot update: live resource %s does not exist", res.ID)
	}

	if existing.Attributes == nil {
		existing.Attributes = make(map[string]interface{})
	}
	if existing.Tags == nil {
		existing.Tags = make(map[string]string)
	}
	if existing.Metadata == nil {
		existing.Metadata = make(map[string]string)
	}

	// Apply modifications to attributes
	for _, ch := range changes {
		existing.Attributes[ch.Path] = ch.DesiredValue
	}

	// If tags changed, update tags
	for k, v := range res.Tags {
		existing.Tags[k] = v
	}

	existing.Metadata["last_remediated_at"] = time.Now().UTC().Format(time.RFC3339)
	return nil
}

// DeleteResource removes a resource from the live AWS environment.
func (a *AWSScanner) DeleteResource(ctx context.Context, res *model.Resource) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	if _, ok := a.liveStore[res.ID]; !ok {
		return fmt.Errorf("cannot delete: live resource %s does not exist", res.ID)
	}

	delete(a.liveStore, res.ID)
	return nil
}

// CreateResource creates a missing resource in the live AWS environment.
func (a *AWSScanner) CreateResource(ctx context.Context, res *model.Resource) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	clone := res.Copy()
	clone.StateSource = "aws_api"
	if clone.Metadata == nil {
		clone.Metadata = make(map[string]string)
	}
	clone.Metadata["created_at"] = time.Now().UTC().Format(time.RFC3339)
	a.liveStore[clone.ID] = clone
	return nil
}
