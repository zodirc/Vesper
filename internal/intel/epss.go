package intel

import (
	"encoding/csv"
	"fmt"
	"io"
	"strconv"
	"strings"
)

func parseEPSS(document []byte) ([]Record, error) {
	text := string(bytesTrim(document))
	lines := strings.Split(text, "\n")
	start := 0
	for start < len(lines) && (strings.TrimSpace(lines[start]) == "" || strings.HasPrefix(strings.TrimSpace(lines[start]), "#")) {
		start++
	}
	if start >= len(lines) {
		return nil, fmt.Errorf("epss document has no header")
	}
	reader := csv.NewReader(strings.NewReader(strings.Join(lines[start:], "\n")))
	reader.FieldsPerRecord = -1
	header, err := reader.Read()
	if err != nil {
		return nil, fmt.Errorf("parse epss header: %w", err)
	}
	if len(header) < 2 || strings.ToLower(strings.TrimSpace(header[0])) != "cve" || strings.ToLower(strings.TrimSpace(header[1])) != "epss" {
		return nil, fmt.Errorf("epss header must start with cve,epss")
	}
	var out []Record
	for {
		row, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("parse epss row: %w", err)
		}
		if len(row) == 0 || strings.TrimSpace(strings.Join(row, "")) == "" {
			continue
		}
		if len(row) < 2 {
			return nil, fmt.Errorf("epss row %q is missing a score", row)
		}
		cve := strings.TrimSpace(row[0])
		if !cveID(cve) {
			return nil, fmt.Errorf("epss record %q is not a CVE id", cve)
		}
		score, err := strconv.ParseFloat(strings.TrimSpace(row[1]), 64)
		if err != nil {
			return nil, fmt.Errorf("epss score for %s: %w", cve, err)
		}
		if score < 0 || score > 1 {
			return nil, fmt.Errorf("epss score %v for %s is outside 0 to 1", score, cve)
		}
		if len(row) > 2 && strings.TrimSpace(row[2]) != "" {
			percentile, err := strconv.ParseFloat(strings.TrimSpace(row[2]), 64)
			if err != nil {
				return nil, fmt.Errorf("epss percentile for %s: %w", cve, err)
			}
			if percentile < 0 || percentile > 1 {
				return nil, fmt.Errorf("epss percentile %v for %s is outside 0 to 1", percentile, cve)
			}
		}
		value := score
		raw := []byte(cve + "," + strings.TrimSpace(row[1]))
		out = append(out, Record{SourceRecordID: cve, VulnerabilityID: cve, EPSS: &value, Raw: raw})
	}
	return out, nil
}
