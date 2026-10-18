package scanner

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/ER-brocode/cloud-drift-remediator/pkg/model"
)

// LiveScanner defines the discovery contract for querying real-time cloud infrastructure.
type LiveScanner interface {
	ProviderName() model.CloudProvider
	SupportedTypes() []model.ResourceType
	DiscoverResources(ctx context.Context, types []model.ResourceType) ([]*model.Resource, error)
	FetchResource(ctx context.Context, resType model.ResourceType, id string) (*model.Resource, error)
	UpdateResource(ctx context.Context, res *model.Resource, changes []model.FieldDiff) error
	DeleteResource(ctx context.Context, res *model.Resource) error
	CreateResource(ctx context.Context, res *model.Resource) error
}

// MultiCloudScanner orchestrates parallel discovery across multiple cloud provider scanners.
type MultiCloudScanner struct {
	scanners map[model.CloudProvider]LiveScanner
	mu       sync.RWMutex
}

// NewMultiCloudScanner initializes an empty multi-cloud scanner coordinator.
func NewMultiCloudScanner() *MultiCloudScanner {
	return &MultiCloudScanner{
		scanners: make(map[model.CloudProvider]LiveScanner),
	}
}

// RegisterScanner attaches a provider-specific live scanner implementation.
func (m *MultiCloudScanner) RegisterScanner(scanner LiveScanner) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.scanners[scanner.ProviderName()] = scanner
}

// GetScanner retrieves a provider scanner.
func (m *MultiCloudScanner) GetScanner(provider model.CloudProvider) (LiveScanner, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	s, ok := m.scanners[provider]
	return s, ok
}

// DiscoverAll concurrently scans registered cloud providers for live infrastructure state.
func (m *MultiCloudScanner) DiscoverAll(ctx context.Context, desired []*model.Resource) ([]*model.Resource, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	// Categorize needed resource types per provider
	providerTypes := make(map[model.CloudProvider]map[model.ResourceType]bool)
	for _, res := range desired {
		if _, ok := providerTypes[res.Provider]; !ok {
			providerTypes[res.Provider] = make(map[model.ResourceType]bool)
		}
		providerTypes[res.Provider][res.Type] = true
	}

	type scanResult struct {
		resources []*model.Resource
		err       error
	}

	resultChan := make(chan scanResult, len(m.scanners))
	var wg sync.WaitGroup

	for prov, scanner := range m.scanners {
		wg.Add(1)
		go func(p model.CloudProvider, s LiveScanner) {
			defer wg.Done()

			var typesToScan []model.ResourceType
			if typeSet, ok := providerTypes[p]; ok {
				for t := range typeSet {
					typesToScan = append(typesToScan, t)
				}
			} else {
				// If no specific desired types, query all supported
				typesToScan = s.SupportedTypes()
			}

			scanCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
			defer cancel()

			res, err := s.DiscoverResources(scanCtx, typesToScan)
			resultChan <- scanResult{resources: res, err: err}
		}(prov, scanner)
	}

	wg.Wait()
	close(resultChan)

	var allResources []*model.Resource
	var errs []error

	for res := range resultChan {
		if res.err != nil {
			errs = append(errs, res.err)
			continue
		}
		allResources = append(allResources, res.resources...)
	}

	if len(errs) > 0 && len(allResources) == 0 {
		return nil, fmt.Errorf("all provider live scans failed: %v", errs)
	}

	return allResources, nil
}
