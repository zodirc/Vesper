package control

import (
	"encoding/json"
	"strings"

	"github.com/zodirc/Vesper/internal/assess"
	"github.com/zodirc/Vesper/internal/id"
	"github.com/zodirc/Vesper/internal/task"
)

// judgeDistroPackages 用发行版公告比较本次主机采集到的软件包版本。
// judgeDistroPackages compares installed package versions with distribution advisories.
//
// 只有公告里的发行版与 collect_os_info 一致时才比较。代号与 version_codename 一致，或者发行版号与 version_id 一致或互为前缀。dpkg 包名、source_package 或 rpm 包名与公告包名一致。deb 使用 Debian 版本规则，rpm 使用 epoch、version 和 release，因此回补版本不会被当成上游版本区间。同一软件包、同一漏洞同时出现受影响和不受影响时记为 conflict，不归并 Finding。配置约束仍使受影响结论降为证据不足。runID 为空时读取全部主机观察，供重新评估使用。
// A comparison happens only when the advisory distribution matches collect_os_info. The codename matches version_codename, or the release matches version_id or one is a prefix of the other. The dpkg package name, source_package, or rpm package name must match the advisory package. deb uses Debian version rules and rpm uses epoch, version, and release, so a backport is not treated as an upstream version range. Affected and not-affected results for the same package and vulnerability become conflict and do not merge a Finding. A configuration constraint still downgrades an affected result to insufficient evidence. An empty runID reads every host observation and is used by reassessment.
func (s *Service) judgeDistroPackages(snapshotID, runID id.ID) error {
	index := map[string][]assess.Statement{}
	for _, statement := range s.statementsIn(snapshotID) {
		distribution, release, ok := distroConstraint(statement.PlatformConstraints)
		if !ok || statement.ProductKey == "" || (statement.Ecosystem != "deb" && statement.Ecosystem != "rpm" && statement.Ecosystem != "apk") {
			continue
		}
		key := distribution + "\x00" + release + "\x00" + distroPackageName(statement)
		index[key] = append(index[key], statement)
	}
	if len(index) == 0 {
		return nil
	}
	type host struct {
		os       Observation
		packages Observation
	}
	hosts := map[string]*host{}
	for _, item := range s.observations {
		if !runID.IsZero() && item.ScanRunID != runID {
			continue
		}
		if item.Type != "host_inventory" || item.ResultStatus != "observed" || item.AssetID.IsZero() {
			continue
		}
		key := item.ScanRunID.String() + "|" + item.AssetID.String()
		slot := hosts[key]
		if slot == nil {
			slot = &host{}
			hosts[key] = slot
		}
		switch item.SubjectKey {
		case "local:collect_os_info":
			if slot.os.CollectedAt.IsZero() || !item.CollectedAt.Before(slot.os.CollectedAt) {
				slot.os = item
			}
		case "local:collect_packages":
			if slot.packages.CollectedAt.IsZero() || !item.CollectedAt.Before(slot.packages.CollectedAt) {
				slot.packages = item
			}
		}
	}
	for _, slot := range hosts {
		if slot.os.ID.IsZero() || slot.packages.ID.IsZero() {
			continue
		}
		distribution := lowerString(slot.os.Value["id"])
		codename := lowerString(slot.os.Value["version_codename"])
		versionID := lowerString(slot.os.Value["version_id"])
		if distribution == "" || (codename == "" && versionID == "") {
			continue
		}
		var assessmentID id.ID
		var batch []packageJudgment
		seen := map[string]struct{}{}
		for _, pkg := range installedPackages(slot.packages.Value) {
			names := []string{pkg.name}
			if pkg.sourcePackage != "" && pkg.sourcePackage != pkg.name {
				names = append(names, pkg.sourcePackage)
			}
			version := packageVersion(pkg)
			for _, name := range names {
				for _, statement := range statementsForPackage(index, distribution, codename, versionID, name) {
					result := assess.Judge(statement.Ecosystem, version, statement)
					if result == assess.Affected && hasConstraint(statement.ConfigurationConstraints) {
						result = assess.InsufficientEvidence
					}
					batch = append(batch, packageJudgment{statement: statement, result: result, pkg: pkg, version: version})
				}
			}
		}
		markPackageContradictions(batch)
		for _, item := range batch {
			marker := item.statement.VulnerabilityID + "|" + item.pkg.name + "|" + item.version + "|" + item.result
			if _, ok := seen[marker]; ok {
				continue
			}
			seen[marker] = struct{}{}
			if assessmentID.IsZero() {
				var err error
				assessmentID, err = id.New()
				if err != nil {
					return err
				}
			}
			detection := Detection{
				AssessmentRunID: assessmentID, Executor: "applicability",
				SubjectType: "software_package", SubjectID: slot.packages.AssetID,
				VulnerabilityID: item.statement.VulnerabilityID, ResultStatus: mapApplicability(item.result), Severity: item.statement.Severity,
				Summary: item.result, InputObservationIDs: []id.ID{slot.os.ID, slot.packages.ID},
				IntelSnapshotID: snapshotID, EvaluatedAt: s.now(),
			}
			if s.duplicateDetection(detection) {
				continue
			}
			detectionID, err := id.New()
			if err != nil {
				return err
			}
			detection.ID = detectionID
			s.detections = append(s.detections, detection)
			if detection.ResultStatus != "confirmed" {
				continue
			}
			s.mergeFinding(id.ID{}, slot.packages.AssetID, item.statement.VulnerabilityID, detectionID, assessmentID, item.pkg.name+" "+item.version, "vulnerability", item.statement.Severity, nil, id.ID{}, id.ID{})
		}
	}
	return nil
}

func (s *Service) judgeCollectedPackages(lease task.Lease) error {
	run, _, err := s.tasks.Snapshot(lease.RunID)
	if err != nil {
		return err
	}
	return s.judgeDistroPackages(run.IntelSnapshotID, lease.RunID)
}

type packageJudgment struct {
	statement assess.Statement
	result    string
	pkg       installedPackage
	version   string
}

type installedPackage struct {
	name          string
	version       string
	epoch         string
	release       string
	source        string
	sourcePackage string
}

func installedPackages(value map[string]any) []installedPackage {
	if value == nil {
		return nil
	}
	var out []installedPackage
	switch items := value["packages"].(type) {
	case []map[string]any:
		for _, item := range items {
			out = append(out, packageFromMap(item))
		}
	case []any:
		for _, item := range items {
			fields, ok := item.(map[string]any)
			if !ok {
				continue
			}
			out = append(out, packageFromMap(fields))
		}
	}
	var kept []installedPackage
	for _, item := range out {
		if item.name == "" || item.version == "" || (item.source != "dpkg" && item.source != "rpm" && item.source != "apk") {
			continue
		}
		kept = append(kept, item)
	}
	return kept
}

func packageFromMap(item map[string]any) installedPackage {
	return installedPackage{
		name: stringField(item["name"]), version: stringField(item["version"]),
		epoch: stringField(item["epoch"]), release: stringField(item["release"]),
		source: stringField(item["source"]), sourcePackage: stringField(item["source_package"]),
	}
}

func packageVersion(pkg installedPackage) string {
	if pkg.source != "rpm" {
		return pkg.version
	}
	epoch := pkg.epoch
	if epoch == "" || epoch == "(none)" {
		epoch = "0"
	}
	if pkg.release == "" {
		return epoch + ":" + pkg.version
	}
	return epoch + ":" + pkg.version + "-" + pkg.release
}

func statementsForPackage(index map[string][]assess.Statement, hostID, codename, versionID, name string) []assess.Statement {
	var out []assess.Statement
	for key, statements := range index {
		parts := strings.Split(key, "\x00")
		if len(parts) != 3 || parts[2] != name {
			continue
		}
		if !distributionMatches(hostID, parts[0]) || !releaseMatches(codename, versionID, parts[1]) {
			continue
		}
		out = append(out, statements...)
	}
	return out
}

func distributionMatches(hostID, distribution string) bool {
	hostID = strings.ToLower(hostID)
	distribution = strings.ToLower(distribution)
	if hostID == distribution {
		return true
	}
	switch distribution {
	case "rhel", "redhat", "red hat":
		return hostID == "rhel" || hostID == "redhat"
	case "almalinux", "alma linux", "alma":
		return hostID == "almalinux"
	case "rocky", "rocky linux":
		return hostID == "rocky"
	case "suse", "sles":
		return hostID == "sles" || hostID == "suse"
	case "opensuse", "opensuse leap", "opensuse-leap":
		return hostID == "opensuse" || hostID == "opensuse-leap" || hostID == "opensuse-tumbleweed"
	default:
		return false
	}
}

func releaseMatches(codename, versionID, release string) bool {
	release = strings.ToLower(strings.TrimPrefix(release, "v"))
	if release == "" {
		return false
	}
	if codename != "" && strings.ToLower(codename) == release {
		return true
	}
	versionID = strings.ToLower(strings.TrimPrefix(versionID, "v"))
	if versionID == "" {
		return false
	}
	return versionID == release || strings.HasPrefix(versionID, release+".") || strings.HasPrefix(release, versionID+".")
}

func distroPackageName(statement assess.Statement) string {
	var body struct {
		Package string `json:"package"`
	}
	if len(statement.PlatformConstraints) > 0 && json.Unmarshal(statement.PlatformConstraints, &body) == nil && body.Package != "" {
		return body.Package
	}
	return statement.ProductKey
}

func markPackageContradictions(batch []packageJudgment) {
	type flags struct{ affected, clear bool }
	groups := map[string]*flags{}
	for i := range batch {
		key := batch[i].pkg.name + "\x00" + batch[i].statement.VulnerabilityID
		group := groups[key]
		if group == nil {
			group = &flags{}
			groups[key] = group
		}
		switch batch[i].result {
		case assess.Affected:
			group.affected = true
		case assess.NotAffected:
			group.clear = true
		}
	}
	for i := range batch {
		group := groups[batch[i].pkg.name+"\x00"+batch[i].statement.VulnerabilityID]
		if group.affected && group.clear && (batch[i].result == assess.Affected || batch[i].result == assess.NotAffected) {
			batch[i].result = assess.Conflict
		}
	}
}

func stringField(value any) string {
	text, _ := value.(string)
	return text
}

func lowerString(value any) string {
	return strings.ToLower(stringField(value))
}

func distroConstraint(raw json.RawMessage) (string, string, bool) {
	if len(raw) == 0 {
		return "", "", false
	}
	var body struct {
		Distribution string `json:"distribution"`
		Release      string `json:"release"`
	}
	if err := json.Unmarshal(raw, &body); err != nil {
		return "", "", false
	}
	if body.Distribution == "" || body.Release == "" {
		return "", "", false
	}
	return body.Distribution, body.Release, true
}
