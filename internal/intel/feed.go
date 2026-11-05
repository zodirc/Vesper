package intel

import (
	"net/url"
	"strconv"
	"time"
)

const (
	// NVDFeedURL 是 NVD CVE API 2.0 的分页地址。
	// NVDFeedURL is the paginated NVD CVE API 2.0 address.
	NVDFeedURL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
	// KEVFeedURL 是 CISA 已知被利用漏洞目录的当前文件。
	// KEVFeedURL is the current CISA Known Exploited Vulnerabilities catalog file.
	KEVFeedURL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
	// EPSSFeedURL 是 FIRST 当前 EPSS 分数的压缩 CSV。
	// EPSSFeedURL is the gzip-compressed CSV of the current FIRST EPSS scores.
	EPSSFeedURL = "https://epss.cyentia.com/epss_scores-current.csv.gz"
	// NVDPageSize 是一次 NVD 请求的结果页大小。一页保持在单次导入的字节上限以内。
	// NVDPageSize is the number of NVD results requested at once. One page stays within the single-import byte limit.
	NVDPageSize = 100
	// NVDWindow 是 NVD lastMod 参数允许的最长区间。
	// NVDWindow is the longest interval the NVD lastMod parameters accept.
	NVDWindow = 120 * 24 * time.Hour
)

// NVDCursor 是 NVD 增量同步的位置。窗口最长 120 天，窗口内按起始下标翻页。
// NVDCursor is the position of an incremental NVD synchronization. A window is at most 120 days, and pages advance by start index inside the window.
type NVDCursor struct {
	WindowStart time.Time `json:"window_start"`
	WindowEnd   time.Time `json:"window_end"`
	StartIndex  int       `json:"start_index"`
}

// InitialNVDCursor 从当前时间向前取一个 120 天窗口。
// InitialNVDCursor takes one 120-day window ending at the current time.
func InitialNVDCursor(now time.Time) NVDCursor {
	end := now.UTC()
	return NVDCursor{WindowStart: end.Add(-NVDWindow), WindowEnd: end}
}

// AdvanceNVDCursor 在一页导入之后计算下一次请求的位置。
// AdvanceNVDCursor calculates the next request position after one page has been imported.
//
// returned 是这一页实际包含的漏洞数。总数还没有读完时只增加起始下标。当前窗口早于现在时继续下一个窗口，否则从窗口结束前一秒重新对齐到现在。
// returned is the number of vulnerabilities actually present on the page. The start index advances while the total is unread. A window that ends before now continues into the next window; otherwise the cursor realigns from one second before the window end through now.
func AdvanceNVDCursor(current NVDCursor, now time.Time, total, returned int) NVDCursor {
	now = now.UTC()
	current.WindowStart = current.WindowStart.UTC()
	current.WindowEnd = current.WindowEnd.UTC()
	nextIndex := current.StartIndex + returned
	if returned > 0 && total > nextIndex {
		current.StartIndex = nextIndex
		return current
	}
	if current.WindowEnd.Before(now) {
		start := current.WindowEnd
		end := start.Add(NVDWindow)
		if end.After(now) {
			end = now
		}
		return NVDCursor{WindowStart: start, WindowEnd: end}
	}
	start := current.WindowEnd.Add(-time.Second)
	oldest := now.Add(-NVDWindow)
	if start.Before(oldest) {
		start = oldest
	}
	return NVDCursor{WindowStart: start, WindowEnd: now}
}

// NVDFeedRequest 生成一页 NVD 请求的 URL。
// NVDFeedRequest builds the URL for one NVD page request.
func NVDFeedRequest(base string, cursor NVDCursor) (string, error) {
	parsed, err := url.Parse(base)
	if err != nil {
		return "", err
	}
	query := parsed.Query()
	query.Set("resultsPerPage", strconv.Itoa(NVDPageSize))
	query.Set("startIndex", strconv.Itoa(cursor.StartIndex))
	query.Set("lastModStartDate", cursor.WindowStart.UTC().Format("2006-01-02T15:04:05.000"))
	query.Set("lastModEndDate", cursor.WindowEnd.UTC().Format("2006-01-02T15:04:05.000"))
	parsed.RawQuery = query.Encode()
	return parsed.String(), nil
}
