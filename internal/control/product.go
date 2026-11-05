package control

import (
	"context"
	"fmt"
	"strings"

	"github.com/zodirc/Vesper/internal/id"
	"github.com/zodirc/Vesper/internal/identity"
)

// AddProductIdentity 登记规范产品及其别名。
// AddProductIdentity records a canonical product and its aliases.
//
// 生态名会写成小写。CPE 必须是 CPE 2.3 的 13 个字段，PURL 必须带类型和名称。别名类型只接受 product_name、vendor_name、package_name、cpe 和 purl。相同 canonical_key 已存在时拒绝。目录没有给出生效区间，因此不保存 valid_from 和 valid_until。
// The ecosystem is stored in lower case. A CPE must be a 13-field CPE 2.3 name, and a PURL must include a type and a name. Alias types are product_name, vendor_name, package_name, cpe, and purl. An existing canonical_key is rejected. valid_from and valid_until are not stored because the catalog input has no effective interval.
func (s *Service) AddProductIdentity(product Product, aliases []identity.Alias) (Product, error) {
	normalized, prepared, err := normalizeProduct(product, aliases)
	if err != nil {
		return Product{}, err
	}
	productID, err := id.New()
	if err != nil {
		return Product{}, err
	}
	normalized.ID = productID
	for i := range prepared {
		aliasID, err := id.New()
		if err != nil {
			return Product{}, err
		}
		prepared[i].ID = aliasID
		prepared[i].ProductID = productID
		prepared[i].Ecosystem = normalized.Ecosystem
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, existing := range s.products {
		if existing.CanonicalKey == normalized.CanonicalKey {
			return Product{}, fmt.Errorf("product %s is already registered", normalized.CanonicalKey)
		}
	}
	s.products[productID] = normalized
	s.aliases = append(s.aliases, prepared...)
	if err := s.flush(context.Background()); err != nil {
		return Product{}, err
	}
	return normalized, nil
}

func normalizeProduct(product Product, aliases []identity.Alias) (Product, []identity.Alias, error) {
	product.Ecosystem = strings.ToLower(strings.TrimSpace(product.Ecosystem))
	product.ProductName = strings.TrimSpace(product.ProductName)
	product.CanonicalKey = strings.TrimSpace(product.CanonicalKey)
	product.Vendor = strings.TrimSpace(product.Vendor)
	product.ProductFamily = strings.TrimSpace(product.ProductFamily)
	product.CPE23 = strings.TrimSpace(product.CPE23)
	product.PURL = strings.TrimSpace(product.PURL)
	if !catalogToken(product.Ecosystem) || !catalogText(product.ProductName, 200) || !catalogText(product.CanonicalKey, 300) {
		return Product{}, nil, fmt.Errorf("product identity is missing an ecosystem, name, or canonical key")
	}
	if product.Vendor != "" && !catalogText(product.Vendor, 200) {
		return Product{}, nil, fmt.Errorf("product vendor is empty or longer than 200 characters")
	}
	if product.ProductFamily != "" && !catalogText(product.ProductFamily, 200) {
		return Product{}, nil, fmt.Errorf("product family is empty or longer than 200 characters")
	}
	if product.CPE23 != "" {
		canonical, ok := canonicalCPE(product.CPE23)
		if !ok {
			return Product{}, nil, fmt.Errorf("product cpe is not a cpe 2.3 name")
		}
		product.CPE23 = canonical
	}
	if product.PURL != "" && !validPURL(product.PURL) {
		return Product{}, nil, fmt.Errorf("product purl has no type or name")
	}
	if len(aliases) == 0 {
		return Product{}, nil, fmt.Errorf("product %s has no alias", product.CanonicalKey)
	}
	prepared := make([]identity.Alias, len(aliases))
	for i, alias := range aliases {
		alias.Value = strings.TrimSpace(alias.Value)
		alias.AliasType = strings.TrimSpace(alias.AliasType)
		alias.Source = strings.TrimSpace(alias.Source)
		if alias.Source == "" {
			alias.Source = "catalog"
		}
		if alias.AliasType == "cpe" {
			canonical, ok := canonicalCPE(alias.Value)
			if !ok {
				return Product{}, nil, fmt.Errorf("product alias %d is not a cpe 2.3 name", i)
			}
			alias.Value = canonical
		}
		if !catalogText(alias.Value, 512) || !catalogText(alias.Source, 100) || !validAlias(alias) {
			return Product{}, nil, fmt.Errorf("product alias %d is not a product name, vendor name, package name, cpe, or purl", i)
		}
		prepared[i] = alias
	}
	return product, prepared, nil
}

func validAlias(alias identity.Alias) bool {
	switch alias.AliasType {
	case "product_name", "vendor_name", "package_name":
		return true
	case "cpe":
		_, ok := canonicalCPE(alias.Value)
		return ok
	case "purl":
		return validPURL(alias.Value)
	default:
		return false
	}
}

func catalogToken(value string) bool {
	if value == "" || len(value) > 64 {
		return false
	}
	for _, r := range value {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '.' || r == '_' || r == '+' || r == '-' {
			continue
		}
		return false
	}
	return true
}

func catalogText(value string, limit int) bool {
	return value != "" && len(value) <= limit && !strings.Contains(value, "\x00")
}

func canonicalCPE(value string) (string, bool) {
	parts, ok := splitCPE(value)
	if !ok || parts[0] != "cpe" || parts[1] != "2.3" {
		return "", false
	}
	switch parts[2] {
	case "a", "h", "o", "A", "H", "O", "*":
	default:
		return "", false
	}
	for _, part := range parts {
		if part == "" {
			return "", false
		}
	}
	if strings.Contains(value, `\`) {
		return value, true
	}
	return strings.ToLower(value), true
}

func splitCPE(value string) ([]string, bool) {
	var parts []string
	var b strings.Builder
	for i := 0; i < len(value); i++ {
		if value[i] == '\\' && i+1 < len(value) {
			b.WriteByte(value[i])
			i++
			b.WriteByte(value[i])
			continue
		}
		if value[i] == ':' {
			parts = append(parts, b.String())
			b.Reset()
			continue
		}
		b.WriteByte(value[i])
	}
	parts = append(parts, b.String())
	return parts, len(parts) == 13
}

func validPURL(value string) bool {
	if !strings.HasPrefix(value, "pkg:") || strings.ContainsAny(value, " \t\r\n") || strings.Contains(value, "\x00") {
		return false
	}
	rest := strings.TrimPrefix(value, "pkg:")
	rest, _, _ = strings.Cut(rest, "#")
	rest, _, _ = strings.Cut(rest, "?")
	path, _, _ := strings.Cut(rest, "@")
	parts := strings.Split(path, "/")
	return len(parts) >= 2 && parts[0] != "" && parts[len(parts)-1] != ""
}
