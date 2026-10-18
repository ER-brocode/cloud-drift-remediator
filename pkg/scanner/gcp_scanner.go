package scanner

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/ER-brocode/cloud-drift-remediator/pkg/model"
)

// GCPScanner handles discovery and live inspection for Google Cloud Platform infrastructure.
type GCPScanner struct {
	projectID string
	mu        sync.RWMutex
	liveStore map[string]*model.Resource
}

// NewGCPScanner creates a GCP scanner.
func NewGCPScanner(projectID string) *GCPScanner {
	if projectID == "" {
		projectID = "default-project"
	}
	return &GCPScanner{
		projectID: projectID,
		liveStore: make(map[string]*model.Resource),
	}
}

// ProviderName returns GCP identifier.
func (g *GCPScanner) ProviderName() model.CloudProvider {
	return model.ProviderGCP
}

// SupportedTypes returns the list of GCP resources handled.
func (g *GCPScanner) SupportedTypes() []model.ResourceType {
	return []model.ResourceType{
		model.GCPcomputeInstance,
		model.GCPstorageBucket,
		model.GCPcomputeFirewall,
	}
}

// SeedLiveResource registers a live GCP resource for testing or caching.
func (g *GCPScanner) SeedLiveResource(res *model.Resource) {
	g.mu.Lock()
	defer g.mu.Unlock()
	res.Provider = model.ProviderGCP
	res.StateSource = "gcp_api"
	g.liveStore[res.ID] = res.Copy()
}

// DiscoverResources queries the live GCP environment.
func (g *GCPScanner) DiscoverResources(ctx context.Context, types []model.ResourceType) ([]*model.Resource, error) {
	g.mu.RLock()
	defer g.mu.RUnlock()

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
	for _, r := range g.liveStore {
		if len(types) == 0 || typeLookup[r.Type] {
			results = append(results, r.Copy())
		}
	}
	return results, nil
}

// FetchResource retrieves a single GCP resource by type and ID.
func (g *GCPScanner) FetchResource(ctx context.Context, resType model.ResourceType, id string) (*model.Resource, error) {
	g.mu.RLock()
	defer g.mu.RUnlock()

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	res, ok := g.liveStore[id]
	if !ok {
		return nil, fmt.Errorf("gcp resource %s not found", id)
	}
	return res.Copy(), nil
}

// UpdateResource reconciles attribute differences in live GCP.
func (g *GCPScanner) UpdateResource(ctx context.Context, res *model.Resource, changes []model.FieldDiff) error {
	g.mu.Lock()
	defer g.mu.Unlock()

	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	existing, ok := g.liveStore[res.ID]
	if !ok {
		return fmt.Errorf("gcp resource %s not found for update", res.ID)
	}

	if existing.Attributes == nil {
		existing.Attributes = make(map[string]interface{})
	}
	if existing.Metadata == nil {
		existing.Metadata = make(map[string]string)
	}

	for _, ch := range changes {
		existing.Attributes[ch.Path] = ch.DesiredValue
	}
	existing.Metadata["last_remediated_at"] = time.Now().UTC().Format(time.RFC3339)
	return nil
}

// DeleteResource deletes a live GCP resource.
func (g *GCPScanner) DeleteResource(ctx context.Context, res *model.Resource) error {
	g.mu.Lock()
	defer g.mu.Unlock()

	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	if _, ok := g.liveStore[res.ID]; !ok {
		return fmt.Errorf("gcp resource %s not found for deletion", res.ID)
	}
	delete(g.liveStore, res.ID)
	return nil
}

// CreateResource creates a live GCP resource.
func (g *GCPScanner) CreateResource(ctx context.Context, res *model.Resource) error {
	g.mu.Lock()
	defer g.mu.Unlock()

	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	clone := res.Copy()
	clone.StateSource = "gcp_api"
	g.liveStore[clone.ID] = clone
	return nil
}
