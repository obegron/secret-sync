package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"k8s.io/apimachinery/pkg/util/validation"
)

type syncTarget struct {
	Kind      string `json:"kind"`
	Namespace string `json:"namespace"`
	Name      string `json:"name,omitempty"`
}

func (t syncTarget) ID() string {
	if t.Name != "" {
		return fmt.Sprintf("cluster/%s/%s", t.Namespace, t.Name)
	}
	return fmt.Sprintf("cluster/%s", t.Namespace)
}

func (t syncTarget) namespaceID() string {
	return fmt.Sprintf("cluster/%s", t.Namespace)
}

func (t syncTarget) targetName(sourceName string) string {
	if strings.TrimSpace(t.Name) != "" {
		return t.Name
	}
	return sourceName
}

func parseTargets(raw string) ([]syncTarget, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, errors.New("annotation is required and must be a JSON array")
	}

	var targets []syncTarget
	if err := json.Unmarshal([]byte(raw), &targets); err != nil {
		return nil, fmt.Errorf("parse JSON: %w", err)
	}
	if len(targets) == 0 {
		return nil, errors.New("at least one target is required")
	}

	seen := map[string]struct{}{}
	result := make([]syncTarget, 0, len(targets))

	for i, t := range targets {
		t.Kind = strings.ToLower(strings.TrimSpace(t.Kind))
		t.Namespace = strings.TrimSpace(t.Namespace)
		t.Name = strings.TrimSpace(t.Name)

		if t.Namespace == "" {
			return nil, fmt.Errorf("target[%d]: namespace is required", i)
		}
		switch t.Kind {
		case targetKindCluster:
		default:
			return nil, fmt.Errorf("target[%d]: unsupported kind %q (only %q is allowed)", i, t.Kind, targetKindCluster)
		}
		if t.Name != "" {
			if errs := validation.IsDNS1123Subdomain(t.Name); len(errs) > 0 {
				return nil, fmt.Errorf("target[%d]: invalid name %q: %s", i, t.Name, strings.Join(errs, ", "))
			}
		}

		if _, ok := seen[t.ID()]; ok {
			continue
		}
		seen[t.ID()] = struct{}{}
		result = append(result, t)
	}

	return result, nil
}

func parseAllowedTargetIDs(raw string) (map[string]struct{}, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil
	}

	targets, err := parseTargets(raw)
	if err != nil {
		return nil, err
	}

	result := make(map[string]struct{}, len(targets))
	for _, target := range targets {
		result[target.ID()] = struct{}{}
	}
	return result, nil
}
