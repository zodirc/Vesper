package control

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/zodirc/Vesper/internal/intel"
)

// FeedStatus 是一个情报源最近一次同步留下的位置和结果。
// FeedStatus is the position and result left by the latest synchronization of one intelligence feed.
type FeedStatus struct {
	Source     string    `json:"source"`
	Cursor     string    `json:"cursor,omitempty"`
	LastResult string    `json:"last_result,omitempty"`
	UpdatedAt  time.Time `json:"updated_at"`
}

// Feeds 返回已保存的情报同步状态。
// Feeds returns the stored intelligence synchronization states.
func (s *Service) Feeds() []FeedStatus {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]FeedStatus, 0, len(s.feeds))
	for _, item := range s.feeds {
		out = append(out, item)
	}
	return out
}

// SyncFeed 从公开地址拉取一份情报并导入。
// SyncFeed fetches one public intelligence document and imports it.
//
// nvd 每次只请求一页，并把下一页位置写入游标。kev 和 epss 拉取当前全量文件；内容摘要不变时不重复导入。osv 的生态压缩包超过单次文档上限，不在这里拉取。网络失败不发布快照，也不推进游标。
// nvd requests one page and stores the next page position. kev and epss fetch the current full file; an unchanged digest is not imported again. An OSV ecosystem archive exceeds the single-document limit and is not fetched here. A network failure publishes no snapshot and does not advance the cursor.
func (s *Service) SyncFeed(ctx context.Context, source string) (IntelSnapshot, FeedStatus, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	canonical, err := intel.CanonicalSource(source)
	if err != nil {
		return IntelSnapshot{}, FeedStatus{}, err
	}
	switch canonical {
	case intel.SourceNVD, intel.SourceCISAKEV, intel.SourceEPSS:
	case intel.SourceOSV:
		return IntelSnapshot{}, FeedStatus{}, fmt.Errorf("sync feed: osv archive exceeds the %d byte document limit", intel.MaxDocumentBytes)
	default:
		return IntelSnapshot{}, FeedStatus{}, fmt.Errorf("sync feed: %s has no public feed", canonical)
	}
	s.mu.Lock()
	state := s.feeds[canonical]
	client := s.feedClient
	nvdURL, kevURL, epssURL := s.nvdFeedURL, s.kevFeedURL, s.epssFeedURL
	s.mu.Unlock()
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	if nvdURL == "" {
		nvdURL = intel.NVDFeedURL
	}
	if kevURL == "" {
		kevURL = intel.KEVFeedURL
	}
	if epssURL == "" {
		epssURL = intel.EPSSFeedURL
	}
	document, nextCursor, result, err := fetchFeed(ctx, client, canonical, state.Cursor, nvdURL, kevURL, epssURL, s.now().UTC())
	if err != nil {
		return IntelSnapshot{}, FeedStatus{}, err
	}
	var published IntelSnapshot
	if document != nil {
		published, err = s.ImportIntel(ctx, canonical, document)
		if err != nil {
			return IntelSnapshot{}, FeedStatus{}, err
		}
		result = "imported"
	} else if published.ID.IsZero() {
		s.mu.Lock()
		published = s.latestOrZero()
		s.mu.Unlock()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	updated := FeedStatus{Source: canonical, Cursor: nextCursor, LastResult: result, UpdatedAt: s.now().UTC()}
	if err := s.commitState(ctx, func() error {
		if s.feeds == nil {
			s.feeds = map[string]FeedStatus{}
		}
		s.feeds[canonical] = updated
		return nil
	}); err != nil {
		return IntelSnapshot{}, FeedStatus{}, err
	}
	return published, updated, nil
}

func (s *Service) latestOrZero() IntelSnapshot {
	latest, ok := s.latestSnapshot()
	if !ok {
		return IntelSnapshot{}
	}
	return latest
}

func fetchFeed(ctx context.Context, client *http.Client, source, cursor, nvdURL, kevURL, epssURL string, now time.Time) ([]byte, string, string, error) {
	switch source {
	case intel.SourceNVD:
		position, err := decodeNVDCursor(cursor, now)
		if err != nil {
			return nil, "", "", err
		}
		address, err := intel.NVDFeedRequest(nvdURL, position)
		if err != nil {
			return nil, "", "", err
		}
		body, err := fetchLimited(ctx, client, address, nvdAPIKey())
		if err != nil {
			return nil, "", "", err
		}
		var page struct {
			TotalResults    int               `json:"totalResults"`
			Vulnerabilities []json.RawMessage `json:"vulnerabilities"`
		}
		if err := json.Unmarshal(body, &page); err != nil {
			return nil, "", "", fmt.Errorf("sync nvd: %w", err)
		}
		next := intel.AdvanceNVDCursor(position, now, page.TotalResults, len(page.Vulnerabilities))
		encoded, err := json.Marshal(next)
		if err != nil {
			return nil, "", "", err
		}
		if len(page.Vulnerabilities) == 0 {
			return nil, string(encoded), "empty", nil
		}
		return body, string(encoded), "imported", nil
	case intel.SourceCISAKEV:
		body, err := fetchLimited(ctx, client, kevURL, "")
		if err != nil {
			return nil, "", "", err
		}
		return unchangedFeed(body, cursor)
	case intel.SourceEPSS:
		body, err := fetchLimited(ctx, client, epssURL, "")
		if err != nil {
			return nil, "", "", err
		}
		if len(body) >= 2 && body[0] == 0x1f && body[1] == 0x8b {
			reader, err := gzip.NewReader(bytes.NewReader(body))
			if err != nil {
				return nil, "", "", fmt.Errorf("sync epss: %w", err)
			}
			defer reader.Close()
			decoded, err := readLimited(reader, intel.MaxDocumentBytes)
			if err != nil {
				return nil, "", "", fmt.Errorf("sync epss: %w", err)
			}
			body = decoded
		}
		return unchangedFeed(body, cursor)
	default:
		return nil, "", "", fmt.Errorf("sync feed: %s has no public feed", source)
	}
}

func unchangedFeed(body []byte, cursor string) ([]byte, string, string, error) {
	sum := sha256.Sum256(body)
	digest := hex.EncodeToString(sum[:])
	if cursor == digest {
		return nil, digest, "unchanged", nil
	}
	return body, digest, "imported", nil
}

func decodeNVDCursor(cursor string, now time.Time) (intel.NVDCursor, error) {
	if strings.TrimSpace(cursor) == "" {
		return intel.InitialNVDCursor(now), nil
	}
	var position intel.NVDCursor
	if err := json.Unmarshal([]byte(cursor), &position); err != nil {
		return intel.NVDCursor{}, fmt.Errorf("sync nvd: cursor: %w", err)
	}
	if position.WindowStart.IsZero() || position.WindowEnd.IsZero() || position.WindowEnd.Before(position.WindowStart) {
		return intel.NVDCursor{}, fmt.Errorf("sync nvd: cursor window is invalid")
	}
	return position, nil
}

func fetchLimited(ctx context.Context, client *http.Client, address, apiKey string) ([]byte, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, address, nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("User-Agent", "Vesper")
	request.Header.Set("Accept", "application/json, text/csv, application/gzip")
	if apiKey != "" {
		request.Header.Set("apiKey", apiKey)
	}
	response, err := client.Do(request)
	if err != nil {
		return nil, fmt.Errorf("sync feed: %w", err)
	}
	defer response.Body.Close()
	body, err := readLimited(response.Body, intel.MaxDocumentBytes)
	if err != nil {
		return nil, fmt.Errorf("sync feed: %w", err)
	}
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("sync feed: %s returned %s", address, response.Status)
	}
	return body, nil
}

func readLimited(reader io.Reader, limit int) ([]byte, error) {
	body, err := io.ReadAll(io.LimitReader(reader, int64(limit)+1))
	if err != nil {
		return nil, err
	}
	if len(body) > limit {
		return nil, fmt.Errorf("document exceeds %d bytes", limit)
	}
	return body, nil
}

func nvdAPIKey() string {
	return strings.TrimSpace(os.Getenv("NVD_API_KEY"))
}
