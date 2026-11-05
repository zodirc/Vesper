package intel

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

func parseCSAF(document []byte) ([]Record, error) {
	var body struct {
		Document struct {
			Category    string `json:"category"`
			CSAFVersion string `json:"csaf_version"`
			Tracking    struct {
				ID                 string `json:"id"`
				Status             string `json:"status"`
				InitialReleaseDate string `json:"initial_release_date"`
				CurrentReleaseDate string `json:"current_release_date"`
			} `json:"tracking"`
		} `json:"document"`
		ProductTree     csafTree          `json:"product_tree"`
		Vulnerabilities []json.RawMessage `json:"vulnerabilities"`
	}
	if err := json.Unmarshal(document, &body); err != nil {
		return nil, fmt.Errorf("parse csaf document: %w", err)
	}
	if body.Document.CSAFVersion != "2.0" {
		return nil, fmt.Errorf("csaf version %s is not supported", body.Document.CSAFVersion)
	}
	switch body.Document.Category {
	case "csaf_security_advisory", "csaf_vex":
	default:
		return nil, fmt.Errorf("csaf category %s is not supported", body.Document.Category)
	}
	switch body.Document.Tracking.Status {
	case "final", "interim":
	default:
		return nil, fmt.Errorf("csaf tracking status %s is not supported", body.Document.Tracking.Status)
	}
	trackingID := strings.TrimSpace(body.Document.Tracking.ID)
	if trackingID == "" || len(trackingID) > 200 || hasControl(trackingID) {
		return nil, fmt.Errorf("csaf tracking id is invalid")
	}
	published, err := parseTime(body.Document.Tracking.InitialReleaseDate)
	if err != nil {
		return nil, err
	}
	modified, err := parseTime(body.Document.Tracking.CurrentReleaseDate)
	if err != nil {
		return nil, err
	}
	products, err := body.ProductTree.products()
	if err != nil {
		return nil, err
	}
	if len(body.Vulnerabilities) == 0 {
		return nil, fmt.Errorf("csaf %s has no vulnerabilities", trackingID)
	}
	var out []Record
	for _, raw := range body.Vulnerabilities {
		records, err := csafVulnerability(trackingID, raw, products, published, modified)
		if err != nil {
			return nil, err
		}
		out = append(out, records...)
	}
	return out, nil
}

type csafTree struct {
	Branches         []csafBranch  `json:"branches"`
	FullProductNames []csafProduct `json:"full_product_names"`
	Relationships    []struct {
		ProductReference          string      `json:"product_reference"`
		RelatesToProductReference string      `json:"relates_to_product_reference"`
		FullProductName           csafProduct `json:"full_product_name"`
	} `json:"relationships"`
}

type csafBranch struct {
	Category         string        `json:"category"`
	Name             string        `json:"name"`
	Product          *csafProduct  `json:"product"`
	Branches         []csafBranch  `json:"branches"`
	FullProductNames []csafProduct `json:"full_product_names"`
}

type csafProduct struct {
	Name      string `json:"name"`
	ProductID string `json:"product_id"`
	Helper    *struct {
		CPE  string `json:"cpe"`
		PURL string `json:"purl"`
	} `json:"product_identification_helper"`
}

type csafIdentity struct {
	Vendor   string
	Product  string
	Version  string
	CPE      string
	PURL     string
	HasRange bool
}

func (tree csafTree) products() (map[string]csafIdentity, error) {
	found := map[string]csafIdentity{}
	var walk func(branch csafBranch, ctx csafIdentity) error
	walk = func(branch csafBranch, ctx csafIdentity) error {
		switch branch.Category {
		case "vendor":
			ctx.Vendor = strings.TrimSpace(branch.Name)
			ctx.Product = ""
			ctx.Version = ""
			ctx.HasRange = false
		case "product_name", "product_family":
			if branch.Category == "product_name" {
				ctx.Product = strings.TrimSpace(branch.Name)
			}
			ctx.Version = ""
			ctx.HasRange = false
		case "product_version":
			ctx.Version = strings.TrimSpace(branch.Name)
			ctx.HasRange = false
		case "product_version_range":
			ctx.Version = ""
			ctx.HasRange = true
		}
		if branch.Product != nil {
			if err := addCSAFProduct(found, *branch.Product, ctx); err != nil {
				return err
			}
		}
		for _, item := range branch.FullProductNames {
			if err := addCSAFProduct(found, item, ctx); err != nil {
				return err
			}
		}
		for _, child := range branch.Branches {
			if err := walk(child, ctx); err != nil {
				return err
			}
		}
		return nil
	}
	for _, item := range tree.FullProductNames {
		if err := addCSAFProduct(found, item, csafIdentity{}); err != nil {
			return nil, err
		}
	}
	for _, branch := range tree.Branches {
		if err := walk(branch, csafIdentity{}); err != nil {
			return nil, err
		}
	}
	for _, relation := range tree.Relationships {
		base, ok := found[relation.ProductReference]
		if !ok {
			base = found[relation.RelatesToProductReference]
		}
		if err := addCSAFProduct(found, relation.FullProductName, base); err != nil {
			return nil, err
		}
	}
	if len(found) > 20000 {
		return nil, fmt.Errorf("csaf product tree has %d products", len(found))
	}
	return found, nil
}

func addCSAFProduct(found map[string]csafIdentity, product csafProduct, ctx csafIdentity) error {
	id := strings.TrimSpace(product.ProductID)
	if id == "" || len(id) > 256 || hasControl(id) {
		return fmt.Errorf("csaf product id is invalid")
	}
	if _, ok := found[id]; ok {
		return fmt.Errorf("csaf product id %s is duplicated", id)
	}
	if product.Helper != nil {
		if cpe := strings.TrimSpace(product.Helper.CPE); cpe != "" {
			ctx.CPE = cpe
		}
		if purl := strings.TrimSpace(product.Helper.PURL); purl != "" {
			ctx.PURL = purl
		}
	}
	found[id] = ctx
	return nil
}

func csafVulnerability(trackingID string, raw json.RawMessage, products map[string]csafIdentity, published, modified *time.Time) ([]Record, error) {
	var body struct {
		CVE string `json:"cve"`
		IDs []struct {
			Text string `json:"text"`
		} `json:"ids"`
		ProductStatus map[string][]string `json:"product_status"`
		Scores        []struct {
			Products []string `json:"products"`
			CVSSV3   *struct {
				BaseScore    *float64 `json:"baseScore"`
				BaseSeverity string   `json:"baseSeverity"`
			} `json:"cvss_v3"`
		} `json:"scores"`
	}
	if err := json.Unmarshal(raw, &body); err != nil {
		return nil, fmt.Errorf("parse csaf vulnerability: %w", err)
	}
	vulnerabilityID := strings.TrimSpace(body.CVE)
	if vulnerabilityID == "" {
		for _, item := range body.IDs {
			if text := strings.TrimSpace(item.Text); text != "" {
				vulnerabilityID = text
				break
			}
		}
	}
	if vulnerabilityID == "" || len(vulnerabilityID) > 200 || hasControl(vulnerabilityID) {
		return nil, fmt.Errorf("csaf %s vulnerability id is invalid", trackingID)
	}
	if body.CVE != "" && !cveID(body.CVE) {
		return nil, fmt.Errorf("csaf %s cve %s is invalid", trackingID, body.CVE)
	}
	type group struct {
		affected  []string
		excluded  []string
		fixed     []string
		lower     string
		upper     string
		upperOpen bool
	}
	groups := map[string]*group{}
	take := func(selector string) *group {
		item := groups[selector]
		if item == nil {
			item = &group{}
			groups[selector] = item
		}
		return item
	}
	for status, ids := range body.ProductStatus {
		for _, productID := range ids {
			identity, ok := products[productID]
			if !ok {
				return nil, fmt.Errorf("csaf %s references unknown product %s", trackingID, productID)
			}
			selector, ecosystem, version, err := csafSelector(identity)
			if err != nil {
				return nil, fmt.Errorf("csaf %s: %w", trackingID, err)
			}
			if version == "" {
				continue
			}
			key := ecosystem + "\x00" + selector
			item := take(key)
			switch status {
			case "known_affected":
				item.affected = append(item.affected, version)
			case "known_not_affected", "fixed":
				item.excluded = append(item.excluded, version)
				if status == "fixed" {
					item.fixed = append(item.fixed, version)
				}
			case "first_affected":
				if item.lower != "" && item.lower != version {
					return nil, fmt.Errorf("csaf %s has two first affected versions for %s", trackingID, selector)
				}
				item.lower = version
			case "last_affected":
				if item.upper != "" && item.upper != version {
					return nil, fmt.Errorf("csaf %s has two last affected versions for %s", trackingID, selector)
				}
				item.upper = version
				item.upperOpen = false
			case "first_fixed":
				if item.upper != "" && item.upper != version {
					return nil, fmt.Errorf("csaf %s has two fixed bounds for %s", trackingID, selector)
				}
				item.upper = version
				item.upperOpen = true
				item.fixed = append(item.fixed, version)
			case "under_investigation", "recommended":
			default:
				return nil, fmt.Errorf("csaf %s product status %s is not supported", trackingID, status)
			}
		}
	}
	var out []Record
	for key, item := range groups {
		ecosystem, selector, _ := strings.Cut(key, "\x00")
		for _, version := range item.affected {
			for _, other := range item.excluded {
				if version == other {
					return nil, fmt.Errorf("csaf %s lists %s as both affected and excluded", trackingID, version)
				}
			}
		}
		var ranges []Range
		if item.lower != "" || item.upper != "" {
			span := Range{Ecosystem: ecosystem, StartInclusive: item.lower != ""}
			span.Start = item.lower
			if item.upper != "" {
				span.End = item.upper
				span.EndInclusive = !item.upperOpen
			}
			if item.lower == "" && item.upperOpen {
				span = Range{Ecosystem: ecosystem, Start: item.upper, StartInclusive: true, Excluded: true}
			}
			ranges = append(ranges, span)
		}
		for _, version := range item.affected {
			ranges = append(ranges, Range{Ecosystem: ecosystem, Start: version, StartInclusive: true, End: version, EndInclusive: true, Exact: true})
		}
		for _, version := range item.excluded {
			ranges = append(ranges, Range{Ecosystem: ecosystem, Start: version, StartInclusive: true, End: version, EndInclusive: true, Exact: true, Excluded: true})
		}
		if len(ranges) == 0 {
			continue
		}
		level, severityData, err := csafSeverity(body.Scores, products, selector)
		if err != nil {
			return nil, fmt.Errorf("csaf %s: %w", trackingID, err)
		}
		out = append(out, Record{
			SourceRecordID:  trackingID + "#" + vulnerabilityID + "#" + selector,
			VulnerabilityID: vulnerabilityID, Ecosystem: ecosystem, ProductSelector: selector,
			Ranges: ranges, FixedVersions: uniqueStrings(item.fixed), SeverityData: severityData, Severity: level,
			PublishedAt: published, ModifiedAt: modified, Raw: append([]byte(nil), raw...),
		})
	}
	return out, nil
}

func csafSelector(identity csafIdentity) (selector, ecosystem, version string, err error) {
	version = identity.Version
	if identity.PURL != "" {
		parsed, purlVersion, purlType, err := splitPURL(identity.PURL)
		if err != nil {
			return "", "", "", err
		}
		if version == "" {
			version = purlVersion
		} else if purlVersion != "" && purlVersion != version {
			return "", "", "", fmt.Errorf("purl version %s disagrees with product version %s", purlVersion, version)
		}
		return parsed, purlEcosystem(purlType), version, nil
	}
	if identity.CPE != "" {
		if hasControl(identity.CPE) || len(identity.CPE) > 512 {
			return "", "", "", fmt.Errorf("cpe is invalid")
		}
		return identity.CPE, "generic", version, nil
	}
	if identity.Vendor == "" || identity.Product == "" || hasControl(identity.Vendor) || hasControl(identity.Product) {
		return "", "", "", fmt.Errorf("product %s has no purl, cpe, or vendor and product name", identity.Product)
	}
	selector = "csaf:" + identity.Vendor + ":" + identity.Product
	if len(selector) > 512 {
		return "", "", "", fmt.Errorf("product selector is too long")
	}
	return selector, "generic", version, nil
}

func splitPURL(value string) (selector, version, kind string, err error) {
	if !strings.HasPrefix(value, "pkg:") || hasControl(value) || len(value) > 512 {
		return "", "", "", fmt.Errorf("purl %s is invalid", value)
	}
	rest := strings.TrimPrefix(value, "pkg:")
	kind, rest, ok := strings.Cut(rest, "/")
	if !ok || kind == "" || rest == "" {
		return "", "", "", fmt.Errorf("purl %s is invalid", value)
	}
	rest, _, _ = strings.Cut(rest, "?")
	rest, _, _ = strings.Cut(rest, "#")
	name, version, found := strings.Cut(rest, "@")
	if name == "" || strings.Contains(name, "@") {
		return "", "", "", fmt.Errorf("purl %s is invalid", value)
	}
	if !found {
		version = ""
	}
	return "pkg:" + kind + "/" + name, version, kind, nil
}

func purlEcosystem(kind string) string {
	switch strings.ToLower(kind) {
	case "deb", "debian":
		return "deb"
	case "rpm":
		return "rpm"
	case "npm":
		return "npm"
	case "pypi":
		return "pypi"
	case "maven":
		return "maven"
	case "generic":
		return "generic"
	default:
		return strings.ToLower(kind)
	}
}

func csafSeverity(scores []struct {
	Products []string `json:"products"`
	CVSSV3   *struct {
		BaseScore    *float64 `json:"baseScore"`
		BaseSeverity string   `json:"baseSeverity"`
	} `json:"cvss_v3"`
}, products map[string]csafIdentity, selector string) (string, json.RawMessage, error) {
	applies := func(ids []string) bool {
		if len(ids) == 0 {
			return true
		}
		for _, id := range ids {
			identity, ok := products[id]
			if !ok {
				continue
			}
			got, _, _, err := csafSelector(identity)
			if err == nil && got == selector {
				return true
			}
		}
		return false
	}
	var kept []any
	var level string
	for _, score := range scores {
		if score.CVSSV3 == nil || !applies(score.Products) {
			continue
		}
		kept = append(kept, score)
		if level != "" {
			continue
		}
		next, err := severityFromCVSS(score.CVSSV3.BaseSeverity, score.CVSSV3.BaseScore)
		if err != nil {
			return "", nil, err
		}
		level = next
	}
	if len(kept) == 0 {
		return "", nil, nil
	}
	raw, err := json.Marshal(kept)
	if err != nil {
		return "", nil, err
	}
	return level, raw, nil
}

func uniqueStrings(values []string) []string {
	seen := map[string]struct{}{}
	var out []string
	for _, value := range values {
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	return out
}

func hasControl(value string) bool {
	for _, r := range value {
		if r < 0x20 || r == 0x7f {
			return true
		}
	}
	return false
}
