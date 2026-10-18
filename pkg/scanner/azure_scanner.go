package scanner

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/ER-brocode/cloud-drift-remediator/pkg/model"
)

// AzureScanner handles discovery and live inspection for Microsoft Azure infrastructure.
type AzureScanner struct {
	subscriptionID string
	mu             sync.RWMutex
	liveStore      map[string]*model.Resource
}

// NewAzureScanner creates an Azure scanner.
func NewAzureScanner(subscriptionID string) *AzureScanner {
	if subscriptionID == "" {
		subscriptionID = "00000000-0000-0000-0000-000000000000"
	}
	return &AzureScanner{
		subscriptionID: subscriptionID,
		liveStore:      make(map[string]*model.Resource),
	}
}

// ProviderName returns Azure identifier.
func (a *AzureScanner) ProviderName() model.CloudProvider {
	return model.ProviderAzure
}

// SupportedTypes returns the list of Azure resources handled.
func (a *AzureScanner) SupportedTypes() []model.ResourceType {
	return []model.ResourceType{
		model.AzureVirtualMachine,
		model.AzureStorageAccount,
		model.AzureNSG,
	}
}

// SeedLiveResource registers a live Azure resource for testing or caching.
func (a *AzureScanner) SeedLiveResource(res *model.Resource) {
	a.mu.Lock()
	defer a.mu.Unlock()
	res.Provider = model.ProviderAzure
	res.StateSource = "azure_api"
	a.liveStore[res.ID] = res.Copy()
}

// DiscoverResources queries the live Azure environment.
func (a *AzureScanner) DiscoverResources(ctx context.Context, types []model.ResourceType) ([]*model.Resource, error) {
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

// FetchResource retrieves an Azure resource by type and ID.
func (a *AzureScanner) FetchResource(ctx context.Context, resType model.ResourceType, id string) (*model.Resource, error) {
	a.mu.RLock()
	defer a.mu.RUnlock()

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	res, ok := a.liveStore[id]
	if !ok {
		return nil, fmt.Errorf("azure resource %s not found", id)
	}
	return res.Copy(), nil
}

// UpdateResource reconciles attribute differences in live Azure.
func (a *AzureScanner) UpdateResource(ctx context.Context, res *model.Resource, changes []model.FieldDiff) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	existing, ok := a.liveStore[res.ID]
	if !ok {
		return fmt.Errorf("azure resource %s not found for update", res.ID)
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

// DeleteResource deletes an Azure resource.
func (a *AzureScanner) DeleteResource(ctx context.Context, res *model.Resource) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	if _, ok := a.liveStore[res.ID]; !ok {
		return fmt.Errorf("azure resource %s not found for deletion", res.ID)
	}
	delete(a.liveStore, res.ID)
	return nil
}

// CreateResource creates an Azure resource.
func (a *AzureScanner) CreateResource(ctx context.Context, res *model.Resource) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	clone := res.Copy()
	clone.StateSource = "azure_api"
	a.liveStore[clone.ID] = clone
	return nil
}
