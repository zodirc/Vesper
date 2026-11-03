package control

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/zodirc/Vesper/internal/id"
	"github.com/zodirc/Vesper/internal/scope"
)

func textArray(values []string) string {
	if len(values) == 0 {
		return "{}"
	}
	parts := make([]string, len(values))
	for i, value := range values {
		parts[i] = `"` + strings.ReplaceAll(value, `"`, `\"`) + `"`
	}
	return "{" + strings.Join(parts, ",") + "}"
}

func uuidArrayArg(ids []id.ID) any {
	if ids == nil {
		return nil
	}
	return uuidArray(ids)
}

func uuidArray(ids []id.ID) string {
	if len(ids) == 0 {
		return "{}"
	}
	parts := make([]string, len(ids))
	for i, item := range ids {
		parts[i] = item.String()
	}
	return "{" + strings.Join(parts, ",") + "}"
}

func parseIDs(values []string) ([]id.ID, error) {
	out := make([]id.ID, 0, len(values))
	for _, value := range values {
		if value == "" {
			continue
		}
		parsed, err := id.Parse(value)
		if err != nil {
			return nil, err
		}
		out = append(out, parsed)
	}
	return out, nil
}

func idArg(value id.ID) any {
	if value.IsZero() {
		return nil
	}
	return value.String()
}

func textArg(value string) any {
	if value == "" {
		return nil
	}
	return value
}

func timeArg(value *time.Time) any {
	if value == nil || value.IsZero() {
		return nil
	}
	return value.UTC()
}

func jsonArg(value any) (string, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	if len(raw) == 0 || string(raw) == "null" {
		return "{}", nil
	}
	return string(raw), nil
}

func decodeGrant(raw []byte) (scope.Grant, error) {
	var grant scope.Grant
	if err := json.Unmarshal(raw, &grant); err != nil {
		return scope.Grant{}, fmt.Errorf("decode grant snapshot: %w", err)
	}
	selectors := make([]scope.Selector, 0, len(grant.Selectors))
	for _, item := range grant.Selectors {
		parsed, err := scope.ParseSelector(item.Kind, item.Value)
		if err != nil {
			return scope.Grant{}, err
		}
		selectors = append(selectors, parsed)
	}
	grant.Selectors = selectors
	grant.ValidFrom = grant.ValidFrom.UTC()
	if grant.MaxRuntime < 0 {
		return scope.Grant{}, fmt.Errorf("decode grant snapshot: negative runtime")
	}
	return grant, nil
}
