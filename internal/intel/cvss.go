package intel

import (
	"fmt"
	"math"
	"strings"
)

// BaseScore 计算 CVSS 3.0 或 3.1 向量的基础分。无法识别的向量返回错误，不估算分数。
// BaseScore calculates the base score of a CVSS 3.0 or 3.1 vector. An unrecognized vector returns an error and no estimated score.
func BaseScore(vector string) (float64, error) {
	vector = strings.TrimSpace(vector)
	if !strings.HasPrefix(vector, "CVSS:3.0/") && !strings.HasPrefix(vector, "CVSS:3.1/") {
		return 0, fmt.Errorf("cvss vector %s is not version 3.0 or 3.1", vector)
	}
	metrics := map[string]string{}
	for _, part := range strings.Split(vector, "/")[1:] {
		name, value, ok := strings.Cut(part, ":")
		if !ok || name == "" || value == "" {
			return 0, fmt.Errorf("cvss vector %s has an invalid metric", vector)
		}
		if _, exists := metrics[name]; exists {
			return 0, fmt.Errorf("cvss vector %s repeats %s", vector, name)
		}
		metrics[name] = value
	}
	av, err := metric(metrics, "AV", map[string]float64{"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2})
	if err != nil {
		return 0, err
	}
	ac, err := metric(metrics, "AC", map[string]float64{"L": 0.77, "H": 0.44})
	if err != nil {
		return 0, err
	}
	ui, err := metric(metrics, "UI", map[string]float64{"N": 0.85, "R": 0.62})
	if err != nil {
		return 0, err
	}
	scope, ok := metrics["S"]
	if !ok || (scope != "U" && scope != "C") {
		return 0, fmt.Errorf("cvss scope is missing or invalid")
	}
	prValues := map[string]float64{"N": 0.85, "L": 0.62, "H": 0.27}
	if scope == "C" {
		prValues = map[string]float64{"N": 0.85, "L": 0.68, "H": 0.5}
	}
	pr, err := metric(metrics, "PR", prValues)
	if err != nil {
		return 0, err
	}
	c, err := metric(metrics, "C", map[string]float64{"N": 0, "L": 0.22, "H": 0.56})
	if err != nil {
		return 0, err
	}
	i, err := metric(metrics, "I", map[string]float64{"N": 0, "L": 0.22, "H": 0.56})
	if err != nil {
		return 0, err
	}
	a, err := metric(metrics, "A", map[string]float64{"N": 0, "L": 0.22, "H": 0.56})
	if err != nil {
		return 0, err
	}
	iss := 1 - ((1 - c) * (1 - i) * (1 - a))
	var impact float64
	if scope == "U" {
		impact = 6.42 * iss
	} else {
		impact = 7.52*(iss-0.029) - 3.25*math.Pow(iss-0.02, 15)
	}
	if impact <= 0 {
		return 0, nil
	}
	exploitability := 8.22 * av * ac * pr * ui
	score := impact + exploitability
	if scope == "C" {
		score = 1.08 * score
	}
	if score > 10 {
		score = 10
	}
	return roundup(score), nil
}

func metric(metrics map[string]string, name string, values map[string]float64) (float64, error) {
	value, ok := metrics[name]
	if !ok {
		return 0, fmt.Errorf("cvss metric %s is missing", name)
	}
	weight, ok := values[value]
	if !ok {
		return 0, fmt.Errorf("cvss metric %s has value %s", name, value)
	}
	return weight, nil
}

func roundup(value float64) float64 {
	scaled := int64(math.Round(value * 100000))
	if scaled%10000 == 0 {
		return float64(scaled) / 100000
	}
	return float64((scaled/10000)+1) / 10
}
