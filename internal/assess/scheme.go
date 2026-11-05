package assess

import "strings"

// Scheme 返回生态使用的版本比较方案。空字符串表示调用方没有给出生态。
// Scheme returns the version-comparison scheme used by an ecosystem. An empty string means the caller did not name an ecosystem.
//
// deb、rpm、apk、semver、pypi、maven、rubygems、nuget 和 composer 使用各自已发布的规则。git 表示提交区间，没有仓库时不能排序。无法识别的名称返回 unknown。
// deb, rpm, apk, semver, pypi, maven, rubygems, nuget, and composer use their published rules. git names a commit interval and cannot be ordered without a repository. An unrecognized name returns unknown.
func Scheme(ecosystem string) string {
	text := strings.ToLower(strings.TrimSpace(ecosystem))
	if text == "" {
		return ""
	}
	head, _, _ := strings.Cut(text, ":")
	switch head {
	case "generic":
		return "generic"
	case "deb", "debian", "ubuntu":
		return "deb"
	case "rpm", "redhat", "red hat", "rhel", "rocky", "rocky linux", "almalinux", "alma linux", "alma", "fedora", "suse", "sles", "opensuse", "opensuse leap", "mageia":
		return "rpm"
	case "apk", "alpine":
		return "apk"
	case "semver", "npm", "go", "crates.io", "cargo", "hex", "pub", "swift", "swifturl":
		return "semver"
	case "pypi", "pip":
		return "pypi"
	case "maven":
		return "maven"
	case "rubygems", "gem", "ruby":
		return "rubygems"
	case "nuget":
		return "nuget"
	case "packagist", "composer":
		return "composer"
	case "git":
		return "git"
	default:
		return "unknown"
	}
}

func ecosystemsCompatible(left, right string) bool {
	if left == "" || right == "" || strings.EqualFold(left, right) {
		return true
	}
	leftScheme, rightScheme := Scheme(left), Scheme(right)
	if leftScheme == "" || rightScheme == "" || leftScheme != rightScheme || leftScheme == "unknown" || leftScheme == "git" {
		return false
	}
	return strings.EqualFold(left, leftScheme) || strings.EqualFold(right, rightScheme)
}
