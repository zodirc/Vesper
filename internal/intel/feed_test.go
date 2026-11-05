package intel

import (
	"strings"
	"testing"
	"time"
)

func TestNVDCursorPagesThenOpensTheNextWindow(t *testing.T) {
	now := time.Date(2026, 11, 5, 0, 0, 0, 0, time.UTC)
	cursor := InitialNVDCursor(now)
	if !cursor.WindowEnd.Equal(now) || !cursor.WindowStart.Equal(now.Add(-NVDWindow)) || cursor.StartIndex != 0 {
		t.Fatalf("cursor = %+v", cursor)
	}
	address, err := NVDFeedRequest("https://feeds.example/cves", cursor)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(address, "startIndex=0") || !strings.Contains(address, "resultsPerPage=100") || !strings.Contains(address, "lastModStartDate=") {
		t.Fatalf("address = %s", address)
	}
	paged := AdvanceNVDCursor(cursor, now, 250, 100)
	if paged.StartIndex != 100 || !paged.WindowEnd.Equal(now) {
		t.Fatalf("paged = %+v", paged)
	}
	older := cursor
	older.WindowEnd = now.Add(-24 * time.Hour)
	next := AdvanceNVDCursor(older, now, 10, 10)
	if !next.WindowStart.Equal(older.WindowEnd) || next.StartIndex != 0 || !next.WindowEnd.Equal(now) {
		t.Fatalf("next = %+v", next)
	}
	caught := AdvanceNVDCursor(cursor, now, 10, 10)
	if !caught.WindowEnd.Equal(now) || !caught.WindowStart.Equal(now.Add(-time.Second)) {
		t.Fatalf("caught = %+v", caught)
	}
}
