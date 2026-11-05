package control

import (
	"sort"

	"github.com/zodirc/Vesper/internal/asset"
	"github.com/zodirc/Vesper/internal/id"
	"github.com/zodirc/Vesper/internal/scope"
	"github.com/zodirc/Vesper/internal/task"
)

// Grants 返回全部授权副本，按创建时间从新到旧排列。
// Grants returns copies of every grant, newest creation time first.
func (s *Service) Grants() []scope.Grant {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]scope.Grant, 0, len(s.grants))
	for _, grant := range s.grants {
		out = append(out, copyGrant(grant))
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].CreatedAt.Equal(out[j].CreatedAt) {
			return out[i].CreatedAt.After(out[j].CreatedAt)
		}
		return out[i].ID.String() < out[j].ID.String()
	})
	return out
}

func copyGrant(grant scope.Grant) scope.Grant {
	grant.Selectors = append([]scope.Selector(nil), grant.Selectors...)
	grant.AllowedTransports = append([]string(nil), grant.AllowedTransports...)
	grant.Ports = append([]scope.PortRange(nil), grant.Ports...)
	grant.AllowedOperations = append([]string(nil), grant.AllowedOperations...)
	grant.ObservationPointIDs = append([]id.ID(nil), grant.ObservationPointIDs...)
	if grant.SubjectID != nil {
		value := *grant.SubjectID
		grant.SubjectID = &value
	}
	if grant.ValidUntil != nil {
		value := *grant.ValidUntil
		grant.ValidUntil = &value
	}
	if grant.ApprovedBy != nil {
		value := *grant.ApprovedBy
		grant.ApprovedBy = &value
	}
	if grant.ApprovedAt != nil {
		value := *grant.ApprovedAt
		grant.ApprovedAt = &value
	}
	if grant.RevokedAt != nil {
		value := *grant.RevokedAt
		grant.RevokedAt = &value
	}
	return grant
}

// Runs 返回全部扫描运行副本，按创建时间从新到旧排列。
// Runs returns copies of every scan run, newest creation time first.
func (s *Service) Runs() []task.Run {
	s.mu.Lock()
	defer s.mu.Unlock()
	runs, _, _ := s.tasks.Export()
	if runs == nil {
		runs = []task.Run{}
	}
	sort.Slice(runs, func(i, j int) bool {
		if !runs[i].CreatedAt.Equal(runs[j].CreatedAt) {
			return runs[i].CreatedAt.After(runs[j].CreatedAt)
		}
		return runs[i].ID.String() < runs[j].ID.String()
	})
	return runs
}

// Assets 返回由机器标识建立的资产副本。
// Assets returns copies of assets established from a machine identifier.
func (s *Service) Assets() []asset.Asset {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]asset.Asset, 0, len(s.catalog.Assets))
	for _, item := range s.catalog.Assets {
		out = append(out, item)
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].LastObservedAt.Equal(out[j].LastObservedAt) {
			return out[i].LastObservedAt.After(out[j].LastObservedAt)
		}
		return out[i].ID.String() < out[j].ID.String()
	})
	return out
}

// Endpoints 返回端点投影副本。
// Endpoints returns copies of endpoint projections.
func (s *Service) Endpoints() []asset.Endpoint {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]asset.Endpoint, 0, len(s.catalog.Endpoints))
	for _, item := range s.catalog.Endpoints {
		if item.AssetID != nil {
			value := *item.AssetID
			item.AssetID = &value
		}
		out = append(out, item)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Address.String() != out[j].Address.String() {
			return out[i].Address.String() < out[j].Address.String()
		}
		if out[i].Transport != out[j].Transport {
			return out[i].Transport < out[j].Transport
		}
		if out[i].Port != out[j].Port {
			return out[i].Port < out[j].Port
		}
		return out[i].ID.String() < out[j].ID.String()
	})
	return out
}

// Targets 返回扫描目标副本。
// Targets returns copies of scan targets.
func (s *Service) Targets() []asset.Target {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]asset.Target, 0, len(s.catalog.Targets))
	for _, item := range s.catalog.Targets {
		out = append(out, copyTarget(item))
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].CreatedAt.Equal(out[j].CreatedAt) {
			return out[i].CreatedAt.After(out[j].CreatedAt)
		}
		return out[i].ID.String() < out[j].ID.String()
	})
	return out
}

func copyTarget(item asset.Target) asset.Target {
	if item.Address != nil {
		value := *item.Address
		item.Address = &value
	}
	if item.Prefix != nil {
		value := *item.Prefix
		item.Prefix = &value
	}
	if item.Port != nil {
		value := *item.Port
		item.Port = &value
	}
	return item
}
